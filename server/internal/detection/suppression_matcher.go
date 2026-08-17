package detection

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/edr-platform/server/internal/tick"
)

// SuppressionRule is the detection engine's view of a suppression rule.
type SuppressionRule struct {
	ID             string
	Name           string
	RuleName       string // match alert.RuleName (substring, case-insensitive)
	Hostname       string // match alert.Hostname (substring, case-insensitive)
	SeverityMax    int    // suppress if alert.Severity <= SeverityMax (0 = disabled)
	MITRETechnique string // match alert.MITRETech (exact or prefix)
	AgentID        string // match alert.AgentID (exact)
	// CommandLine matches the triggering process's command line (substring,
	// case-insensitive). The dimension operators reach for first when a benign
	// tool trips a rule: the rule is right in general and wrong for this one
	// invocation, and neither the rule name nor the host distinguishes them.
	CommandLine string
	// ParentProcess matches the triggering process's parent image (suffix,
	// case-insensitive), so a whole spawn chain can be excluded without naming
	// every child. "ssm-document-worker.exe" excludes what AWS SSM launches
	// without excluding the same binary launched by anything else.
	ParentProcess string
	ExpiresAt     *time.Time
}

// SuppressionContext carries the parts of the triggering event that the alert
// row itself does not hold. It is deliberately NOT folded into StoredAlert:
// StoredAlert is what gets written to the alerts table, and these fields are
// matching inputs, not columns.
type SuppressionContext struct {
	CommandLine string
	ParentImage string
}

// SuppressionContextFrom reads the matching inputs out of a flattened event.
//
// The parent key is tried in several spellings because the flatteners disagree:
// ingestion emits parent_process, the Sigma alias table also accepts
// parentImagePath / parent_image_path / parentProcessName. Reading one spelling
// would make the condition silently inert for the other paths — the failure mode
// this codebase keeps hitting.
func SuppressionContextFrom(flat map[string]interface{}) SuppressionContext {
	str := func(keys ...string) string {
		for _, k := range keys {
			if v, ok := flat[k].(string); ok && v != "" {
				return v
			}
		}
		return ""
	}
	return SuppressionContext{
		CommandLine: str("command_line", "commandLine", "CommandLine"),
		ParentImage: str("parent_process", "parentProcessName", "parent_image_path", "parentImagePath", "ParentImage"),
	}
}

// SuppressionLoader loads active suppression rules from the data store.
type SuppressionLoader interface {
	ListActiveSuppressions(ctx context.Context) ([]SuppressionRule, error)
}

// SuppressionMatcher caches active suppression rules and evaluates alerts against them.
// Rules are loaded at startup and refreshed every 5 minutes, plus on NATS signal.
type SuppressionMatcher struct {
	loader   SuppressionLoader
	mu       sync.RWMutex
	rules    []SuppressionRule
	loadedAt time.Time
}

// NewSuppressionMatcher creates a SuppressionMatcher backed by the given loader.
func NewSuppressionMatcher(loader SuppressionLoader) *SuppressionMatcher {
	return &SuppressionMatcher{loader: loader}
}

// Start performs an initial load and launches the background refresh goroutine.
func (m *SuppressionMatcher) Start(ctx context.Context) {
	if err := m.load(ctx); err != nil {
		slog.Warn("初期抑制ルール読み込みに失敗しました", "error", err)
	}
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				tick.Run(ctx, "suppression_matcher_refresh", func(ctx context.Context) {
					if err := m.load(ctx); err != nil {
						tick.Fail(ctx, err, "抑制ルールの定期リフレッシュに失敗しました")
					}
				})
			}
		}
	}()
}

// RefreshNow synchronously reloads suppression rules from the store.
func (m *SuppressionMatcher) RefreshNow(ctx context.Context) {
	if err := m.load(ctx); err != nil {
		slog.Warn("抑制ルールの即時リフレッシュに失敗しました", "error", err)
	}
}

func (m *SuppressionMatcher) load(ctx context.Context) error {
	rules, err := m.loader.ListActiveSuppressions(ctx)
	if err != nil {
		return err
	}

	// 広すぎるルールをここで選り分ける。
	//
	// ★ #760 で AlertPipeline に抑制を結線するまで、運用者から見ると「抑制ルールを
	// 作っても何も止まらない」状態だった。効かない原因は条件の狭さではなく結線の
	// 欠落だったが、そうとは分からないので **「効かないからもっと広くしてみる」**
	// という調整が積み上がっている可能性がある。結線した瞬間、それが本当に
	// アラートを消し始める。
	//
	// catch-all は適用しない。matches() が元から「条件ゼロの行」を拒んでいたのと
	// 同じ理由で、`mitre_technique="T"`（前方一致で全技法に当たる）や
	// `severity_max=10`（上限そのもの）は**書かれているだけで条件ゼロと同じ**である。
	// 元のガードが形だけを見ていたのを、意味で見るように広げた。
	//
	// wide は適用する。「severity_max=2 で低ノイズ帯を落とす」のように、絞り込みが
	// 弱くても意図が明確な運用はあり得る。**測っていないものを勝手に止めない**という
	// この一連の作業の方針に従い、警告に留める。棚卸しは
	// `edr-cli suppressions audit` が同じ判定で行う。
	kept := make([]SuppressionRule, 0, len(rules))
	var wide, rejected int
	for _, r := range rules {
		switch breadth, why := ClassifySuppression(r); breadth {
		case SuppressionCatchAll:
			rejected++
			slog.Error("抑制ルールが広すぎるため適用しません（全アラートが消えます）",
				"rule", r.Name, "id", r.ID, "reason", why)
		case SuppressionWide:
			wide++
			kept = append(kept, r)
			slog.Warn("抑制ルールの絞り込みが弱いです（意図した範囲か確認してください）",
				"rule", r.Name, "id", r.ID, "reason", why)
		default:
			kept = append(kept, r)
		}
	}

	m.mu.Lock()
	m.rules = kept
	m.loadedAt = time.Now()
	m.mu.Unlock()
	slog.Info("抑制ルールをロードしました",
		"count", len(kept), "wide", wide, "rejected_catch_all", rejected)
	return nil
}

// IsSuppressed returns (matched, ruleName, ruleID) if the given alert matches
// any active suppression rule.
func (m *SuppressionMatcher) IsSuppressed(alert *StoredAlert, sctx SuppressionContext) (bool, string, string) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	now := time.Now()
	for _, r := range m.rules {
		// Skip expired rules (belt-and-suspenders; loader already filters)
		if r.ExpiresAt != nil && r.ExpiresAt.Before(now) {
			continue
		}
		if m.matches(r, alert, sctx) {
			return true, r.Name, r.ID
		}
	}
	return false, "", ""
}

// matches returns true when ALL non-empty conditions in the rule match the alert.
//
// A rule with NO conditions populated is rejected (returns false) — otherwise
// it would silently suppress every alert produced by the engine. This guard
// prevents an empty `conditions = {}` JSONB row from acting as a catch-all,
// which previously dropped IOC and Sigma alerts indiscriminately.
//
// 2026-08-14: そのガードを**形から意味に**広げた。条件が書かれていても
// `mitre_technique="T"`（前方一致で全技法に当たる）や `severity_max=10`
// （alerts の上限そのもの）は条件ゼロと同じで、元の判定を素通りしていた。
// ClassifySuppression がその判断を持つ（suppression_breadth.go）。
//
// load() でも同じ判定で弾いているので、ここは二重の防御である。ルールが
// loader を経ずに直接差し込まれる経路（テスト、将来の API 直結）でも効かせたい。
func (m *SuppressionMatcher) matches(r SuppressionRule, alert *StoredAlert, sctx SuppressionContext) bool {
	if breadth, _ := ClassifySuppression(r); breadth == SuppressionCatchAll {
		return false
	}
	if r.RuleName != "" {
		if !strings.Contains(strings.ToLower(alert.RuleName), strings.ToLower(r.RuleName)) {
			return false
		}
	}
	if r.Hostname != "" {
		if !strings.Contains(strings.ToLower(alert.Hostname), strings.ToLower(r.Hostname)) {
			return false
		}
	}
	if r.SeverityMax > 0 && alert.Severity > r.SeverityMax {
		return false
	}
	if r.MITRETechnique != "" {
		tech := strings.ToUpper(r.MITRETechnique)
		alertTech := strings.ToUpper(alert.MITRETech)
		if !strings.HasPrefix(alertTech, tech) {
			return false
		}
	}
	if r.AgentID != "" && alert.AgentID != r.AgentID {
		return false
	}
	if r.CommandLine != "" {
		if !strings.Contains(strings.ToLower(sctx.CommandLine), strings.ToLower(r.CommandLine)) {
			return false
		}
	}
	if r.ParentProcess != "" {
		// Suffix, so a rule can name the executable without knowing its path.
		if !strings.HasSuffix(strings.ToLower(sctx.ParentImage), strings.ToLower(r.ParentProcess)) {
			return false
		}
	}
	return true
}

// Count returns the number of cached suppression rules.
func (m *SuppressionMatcher) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.rules)
}
