package detection

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"
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
	ExpiresAt      *time.Time
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
				if err := m.load(ctx); err != nil {
					slog.Warn("抑制ルールの定期リフレッシュに失敗しました", "error", err)
				}
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
	m.mu.Lock()
	m.rules = rules
	m.loadedAt = time.Now()
	m.mu.Unlock()
	slog.Info("抑制ルールをロードしました", "count", len(rules))
	return nil
}

// IsSuppressed returns (matched, ruleName, ruleID) if the given alert matches
// any active suppression rule.
func (m *SuppressionMatcher) IsSuppressed(alert *StoredAlert) (bool, string, string) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	now := time.Now()
	for _, r := range m.rules {
		// Skip expired rules (belt-and-suspenders; loader already filters)
		if r.ExpiresAt != nil && r.ExpiresAt.Before(now) {
			continue
		}
		if m.matches(r, alert) {
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
func (m *SuppressionMatcher) matches(r SuppressionRule, alert *StoredAlert) bool {
	if r.RuleName == "" && r.Hostname == "" && r.SeverityMax == 0 &&
		r.MITRETechnique == "" && r.AgentID == "" {
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
	return true
}

// Count returns the number of cached suppression rules.
func (m *SuppressionMatcher) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.rules)
}
