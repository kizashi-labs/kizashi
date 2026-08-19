package detection

// ユーザー定義アラートルール (custom_alert_rules) の評価。
//
// このテーブルは UI から CRUD できるが、これまで**評価する側が存在しなかった**。
// 唯一それらしい参照が sigma_db.go の
//
//	SELECT rule_yaml AS content FROM custom_alert_rules WHERE enabled = TRUE
//
// だったが、custom_alert_rules に rule_yaml 列は無い (条件を conditions jsonb で
// 持つ構造化テーブルで、Sigma YAML は保持していない)。列が無いのでクエリは毎回
// 失敗し、しかも失敗は Debug ログに落として nil を返す実装だった。つまり
// 「ルールを作れるが、何も起きない」状態が続いていた。
//
// ここで構造化ルールとして正しく評価する。Sigma とは別モデルなので
// SigmaEvaluator には載せない — conditions の AND、event_type による絞り込み、
// time_window_seconds 内で threshold_count に達したら発報、という独自の意味を持つ。

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/edr-platform/server/internal/metrics"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// CustomRuleCondition は 1 条件。suppression.Condition と同じ形。
type CustomRuleCondition struct {
	Field    string `json:"field"`
	Operator string `json:"operator"` // eq, ne, contains, regex, lt, lte, gt, gte
	Value    string `json:"value"`
}

// CustomRule は評価に必要な形へ展開したルール。
type CustomRule struct {
	ID                string
	Name              string
	EventType         string // 空なら全イベント種別が対象
	Conditions        []CustomRuleCondition
	ThresholdCount    int
	TimeWindowSeconds int
	Severity          int
	AlertTitle        string
	AlertDescription  string
	MitreTags         []string

	// compiled は regex オペレータの事前コンパイル結果。条件ごとに
	// 毎イベント regexp.Compile すると評価コストが跳ね上がる。
	compiled map[int]*regexp.Regexp
}

// CustomRuleMatch は閾値に達したルールの発報材料。
type CustomRuleMatch struct {
	Rule  CustomRule
	Count int // 窓内の該当件数 (閾値に達した時点の値)
}

// CustomRuleEvaluator はルール集合と、ルール×エージェントごとの
// スライディングウィンドウを保持する。
type CustomRuleEvaluator struct {
	mu    sync.RWMutex
	rules []CustomRule

	// hits は "ruleID\x00agentID" → 窓内の該当時刻。
	// 閾値 1 のルール (大半) では 1 件入って即座に消えるだけなので、
	// メモリは実質的に「閾値 > 1 のルール × 監視対象エージェント」分。
	hits map[string][]time.Time
}

func NewCustomRuleEvaluator() *CustomRuleEvaluator {
	return &CustomRuleEvaluator{hits: make(map[string][]time.Time)}
}

// RuleCount は読み込み済みのルール数。
func (e *CustomRuleEvaluator) RuleCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.rules)
}

// LoadFromDB は有効なルールを読み直す。
//
// 失敗はエラーとして返す。ここを握りつぶすと「ルールを作ったのに鳴らない」が
// 静かに再発する — この機能がずっと死んでいた原因がまさにそれだった。
func (e *CustomRuleEvaluator) LoadFromDB(ctx context.Context, pool *pgxpool.Pool) error {
	if pool == nil {
		return nil
	}

	rows, err := pool.Query(ctx, `
		SELECT id, name, COALESCE(event_type,''), conditions,
		       threshold_count, time_window_seconds, severity,
		       alert_title, COALESCE(alert_description,''),
		       COALESCE(mitre_tags, '{}')
		FROM custom_alert_rules
		WHERE enabled = TRUE
		ORDER BY created_at ASC`)
	if err != nil {
		return fmt.Errorf("custom_alert_rules query: %w", err)
	}
	defer rows.Close()

	var loaded []CustomRule
	for rows.Next() {
		var (
			r        CustomRule
			condJSON []byte
		)
		if err := rows.Scan(&r.ID, &r.Name, &r.EventType, &condJSON,
			&r.ThresholdCount, &r.TimeWindowSeconds, &r.Severity,
			&r.AlertTitle, &r.AlertDescription, &r.MitreTags); err != nil {
			slog.Warn("custom_rules: 行の読み取りに失敗しました", "error", err)
			continue
		}
		if err := json.Unmarshal(condJSON, &r.Conditions); err != nil {
			// 条件が壊れているルールは「常に一致」でも「常に不一致」でもなく
			// 読み飛ばす。壊れた 1 件で他のルールを巻き添えにしない。
			slog.Warn("custom_rules: conditions の解析に失敗したためこのルールを飛ばします",
				"rule", r.Name, "error", err)
			continue
		}
		r.compiled = compileRegexConditions(r.Name, r.Conditions)
		if r.ThresholdCount < 1 {
			r.ThresholdCount = 1
		}
		loaded = append(loaded, r)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("custom_alert_rules rows: %w", err)
	}

	// 条件は AND なので、1つでも絶対に一致しない条件があればルール全体が
	// 絶対に鳴りません。黙って読み込むと、一覧には有効なルールとして並びます。
	inert := inertRules(loaded)
	for name, reason := range inert {
		slog.Warn("custom_rules: このルールは条件が成立しないため発報しません",
			"rule", name, "reason", reason)
	}

	e.mu.Lock()
	e.rules = loaded
	// ルール定義が変わったら窓もリセットする。閾値や条件を変えたのに
	// 古い計数が残っていると、変更直後に意図しない発報が起きる。
	e.hits = make(map[string][]time.Time)
	e.mu.Unlock()

	slog.Info("custom_rules: ユーザー定義ルールを読み込みました",
		"count", len(loaded), "inert", len(inert))
	return nil
}

// InertRules は「有効だが絶対に一致しない」ルール名 → 理由。
//
// 0 以外は、書いた人が動いていると思っているルールが動いていないという
// ことです。症状は「そのアラートが出ない」だけで、攻撃が無かった環境と
// 区別がつきません。
//
// 読み込み時に別の場所へ控えるのではなく、いま載っているルールから毎回
// 求めます。控える形にすると、控える代入を消しても誰も気づけず、
// ルールが入れ替わったあとの古い一覧が残る余地もできます。
func (e *CustomRuleEvaluator) InertRules() map[string]string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return inertRules(e.rules)
}

// inertRules は、読み込んだルールのうち絶対に一致しないもの → 理由。
//
// 読み込みループから切り出してあります。ループはデータベースが要るので、
// ここに埋め込んだままだと「理由を集めている」と「集めていない」を
// テストが区別できません。実際そうなっていて、集計を丸ごと消す変異が
// 生き残りました。
func inertRules(rules []CustomRule) map[string]string {
	out := map[string]string{}
	for _, r := range rules {
		if why := inertReasons(r.Conditions); len(why) > 0 {
			out[r.Name] = strings.Join(why, "; ")
		}
	}
	return out
}

// inertReasons は、その条件が絶対に一致しない理由を並べます。
//
// 「イベント側の値が数値でない」は不一致で正しく、ここでは見ません。
// 見るのは「ルール側の書き方が壊れている」場合だけです。両者は
// numericCompare の中では同じ `return false` になっていて、区別が
// つきませんでした。
func inertReasons(conds []CustomRuleCondition) []string {
	var out []string
	for _, c := range conds {
		op := strings.ToLower(strings.TrimSpace(c.Operator))
		switch op {
		case "regex":
			if _, err := regexp.Compile(c.Value); err != nil {
				out = append(out, fmt.Sprintf("%s: 正規表現が不正です (%q)", c.Field, c.Value))
			}
		case "lt", "lte", "gt", "gte":
			if _, err := strconv.ParseFloat(strings.TrimSpace(c.Value), 64); err != nil {
				out = append(out, fmt.Sprintf("%s %s %q: 比較対象が数値ではありません", c.Field, op, c.Value))
			}
		case "eq", "ne", "contains", "":
			// 文字列比較。どの値でも成立しうる。
		default:
			out = append(out, fmt.Sprintf("%s: 未対応の演算子 %q", c.Field, c.Operator))
		}
	}
	return out
}

// compileRegexConditions は regex オペレータの条件だけ事前コンパイルする。
// 壊れた正規表現はその条件を「一致しない」として扱う (nil のまま)。
func compileRegexConditions(ruleName string, conds []CustomRuleCondition) map[int]*regexp.Regexp {
	var out map[int]*regexp.Regexp
	for i, c := range conds {
		if !strings.EqualFold(c.Operator, "regex") {
			continue
		}
		re, err := regexp.Compile(c.Value)
		if err != nil {
			metrics.BackgroundFailed("custom_rules", err, "custom_rules: 正規表現が不正なためこの条件は一致しません",
				"rule", ruleName, "pattern", c.Value)
			continue
		}
		if out == nil {
			out = make(map[int]*regexp.Regexp)
		}
		out[i] = re
	}
	return out
}

// EvaluateEvent はイベントを全ルールに当て、閾値に達したものを返す。
func (e *CustomRuleEvaluator) EvaluateEvent(event map[string]interface{}) []CustomRuleMatch {
	return e.evaluateAt(event, time.Now())
}

// evaluateAt は時刻を注入できる評価本体 (窓の挙動をテストするため)。
func (e *CustomRuleEvaluator) evaluateAt(event map[string]interface{}, now time.Time) []CustomRuleMatch {
	e.mu.Lock()
	defer e.mu.Unlock()

	if len(e.rules) == 0 {
		return nil
	}
	agentID, _ := event["agent_id"].(string)

	var matches []CustomRuleMatch
	for _, r := range e.rules {
		if !ruleMatchesEvent(r, event) {
			continue
		}

		// 閾値 1 なら計数を持たずに即発報する。大半のルールがこれで、
		// 窓を持たない分だけ状態も軽い。
		if r.ThresholdCount <= 1 {
			matches = append(matches, CustomRuleMatch{Rule: r, Count: 1})
			continue
		}

		key := r.ID + "\x00" + agentID
		window := time.Duration(r.TimeWindowSeconds) * time.Second
		if window <= 0 {
			window = 5 * time.Minute
		}
		cutoff := now.Add(-window)

		kept := e.hits[key][:0]
		for _, t := range e.hits[key] {
			if t.After(cutoff) {
				kept = append(kept, t)
			}
		}
		kept = append(kept, now)
		e.hits[key] = kept

		if len(kept) >= r.ThresholdCount {
			matches = append(matches, CustomRuleMatch{Rule: r, Count: len(kept)})
			// 発報したら窓をクリアする。残したままだと、閾値に達した後は
			// 窓が空くまで 1 件ごとに鳴り続ける。
			delete(e.hits, key)
		}
	}
	return matches
}

// ruleMatchesEvent は event_type と全条件 (AND) の一致を見る。
func ruleMatchesEvent(r CustomRule, event map[string]interface{}) bool {
	if r.EventType != "" {
		et, _ := event["type"].(string)
		if !strings.EqualFold(et, r.EventType) {
			return false
		}
	}
	// 条件が空のルールは「全イベントに一致」ではなく不一致とする。
	// 設定ミスで作られた空ルールが全イベントを発報するのは危険すぎる。
	if len(r.Conditions) == 0 {
		return false
	}
	for i, c := range r.Conditions {
		if !conditionMatches(c, r.compiled[i], event) {
			return false
		}
	}
	return true
}

func conditionMatches(c CustomRuleCondition, re *regexp.Regexp, event map[string]interface{}) bool {
	raw, ok := event[c.Field]
	if !ok {
		return false
	}
	got := fmt.Sprintf("%v", raw)

	switch strings.ToLower(c.Operator) {
	case "eq", "":
		return strings.EqualFold(got, c.Value)
	case "ne":
		return !strings.EqualFold(got, c.Value)
	case "contains":
		return strings.Contains(strings.ToLower(got), strings.ToLower(c.Value))
	case "regex":
		return re != nil && re.MatchString(got)
	case "lt", "lte", "gt", "gte":
		return numericCompare(strings.ToLower(c.Operator), got, c.Value)
	default:
		return false
	}
}

// numericCompare は数値比較。どちらかが数値でなければ不一致。
func numericCompare(op, got, want string) bool {
	g, err := strconv.ParseFloat(got, 64)
	if err != nil {
		return false
	}
	w, err := strconv.ParseFloat(want, 64)
	if err != nil {
		return false
	}
	switch op {
	case "lt":
		return g < w
	case "lte":
		return g <= w
	case "gt":
		return g > w
	case "gte":
		return g >= w
	}
	return false
}
