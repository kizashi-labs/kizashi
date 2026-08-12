package handlers_test

// 「アラートが 1 件も出ない」系バグの再発防止。
//
// alerts に agent_hostname / agent_os / rule_name / mitre_tactic /
// raw_data / alert_type / category という列は無い。実在するのは
// agent_id・rule_id・title・mitre_technique・source など (migration 001 系)。
//
// これらを参照したクエリは実行時に必ず
// `column "..." does not exist` で落ちるが、呼び出し側は
// `if err == nil` で握りつぶすか空配列を返すだけだったため、
// 画面上は「該当なし」としか見えなかった。
//
// ここでは実 DB にエージェント 1 台とアラートを入れ、各エンドポイントが
// それを拾うことを確認する。列名を誤ると SQL が落ちて 0 件に戻るので、
// この件数アサートがそのまま回帰検出になる。

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/edr-platform/server/internal/api/handlers"
	"github.com/edr-platform/server/internal/reports"
)

// responseContains は JSON レスポンス全体を文字列化して部分一致を見る。
// 「どのキーに出るか」ではなく「出ているか」を確かめたい箇所で使う。
func responseContains(resp map[string]any, needle string) bool {
	b, err := json.Marshal(resp)
	if err != nil {
		return false
	}
	return strings.Contains(string(b), needle)
}

// reportRange はアラート投入時刻を確実に含む期間を返す。
func reportRange() reports.DateRange {
	now := time.Now()
	return reports.DateRange{Start: now.Add(-2 * time.Hour), End: now.Add(time.Hour)}
}

// seedAlertWithRule はエージェント 1 台・rules 1 行・アラート n 件を投入する。
// アラートの半分は rule_id 付き (DB ルール由来)、残りは rule_id なし
// (組み込み検知器由来) にして、両方の経路を通す。
//
// 戻り値は (agentID, hostname, ruleName)。
func seedAlertWithRule(t *testing.T, pool *pgxpool.Pool, tag string) (string, string, string) {
	t.Helper()
	ctx := context.Background()

	hostname := "alertcol-" + tag
	ruleName := "AlertColRule-" + tag

	var agentID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO agents (hostname, os_type, status, last_seen, enrolled_at)
		 VALUES ($1, 'linux', 'online', NOW(), NOW()) RETURNING id::text`,
		hostname).Scan(&agentID); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM agents WHERE id = $1`, agentID) })

	var ruleID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO rules (name, description, type, platform, severity, enabled, content)
		 VALUES ($1, 'regression fixture', 'sigma', ARRAY['linux'], 9, true, '{}') RETURNING id::text`,
		ruleName).Scan(&ruleID); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM rules WHERE id = $1`, ruleID) })

	cleanupAlerts := func() { _, _ = pool.Exec(ctx, `DELETE FROM alerts WHERE agent_id = $1`, agentID) }
	cleanupAlerts()
	t.Cleanup(cleanupAlerts)

	// rules に紐付くアラート 3 件 (T1059 = execution)。
	if _, err := pool.Exec(ctx, `
		INSERT INTO alerts (agent_id, rule_id, severity, title, description, status,
		                    mitre_technique, source, created_at)
		SELECT $1::uuid, $2::uuid, 9, $3, 'd', 'open', 'T1059', 'sigma',
		       NOW() - (g || ' minutes')::INTERVAL
		FROM generate_series(1, 3) g`, agentID, ruleID, "alertcol-titled-"+tag); err != nil {
		t.Fatalf("seed rule-backed alerts: %v", err)
	}

	// rule_id を持たないアラート 2 件 (T1486 = impact)。組み込み検知器由来。
	if _, err := pool.Exec(ctx, `
		INSERT INTO alerts (agent_id, severity, title, description, status,
		                    mitre_technique, source, created_at)
		SELECT $1::uuid, 8, $2, 'd', 'open', 'T1486', 'anomaly',
		       NOW() - (g || ' minutes')::INTERVAL
		FROM generate_series(1, 2) g`, agentID, "alertcol-builtin-"+tag); err != nil {
		t.Fatalf("seed builtin alerts: %v", err)
	}

	return agentID, hostname, ruleName
}

// ── /api/v1/search ───────────────────────────────────────────────

func TestSearch_FindsAlertsByHostnameAndRuleName(t *testing.T) {
	pool := testPool(t)
	_, hostname, ruleName := seedAlertWithRule(t, pool, "search")

	h := handlers.NewSearchHandler(pool)

	// ホスト名で引く (旧: alerts.agent_hostname を見ていて必ず落ちた)。
	code, resp := doJSON(t, http.MethodGet, "/api/v1/search?q="+hostname, nil, h.Search)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %v)", code, resp)
	}
	if n := countAlertResults(t, resp); n == 0 {
		t.Errorf("ホスト名 %q でアラートが 1 件も引けない: %v", hostname, resp)
	}

	// ルール名で引く (旧: alerts.rule_name を見ていて必ず落ちた)。
	code, resp = doJSON(t, http.MethodGet, "/api/v1/search?q="+ruleName, nil, h.Search)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if n := countAlertResults(t, resp); n == 0 {
		t.Errorf("ルール名 %q でアラートが 1 件も引けない: %v", ruleName, resp)
	}
}

// countAlertResults は /search レスポンスから type=alert の件数を数える。
func countAlertResults(t *testing.T, resp map[string]any) int {
	t.Helper()
	items, ok := resp["results"].([]any)
	if !ok {
		return 0
	}
	n := 0
	for _, it := range items {
		m, ok := it.(map[string]any)
		if ok && m["type"] == "alert" {
			n++
		}
	}
	return n
}

// ── /api/v1/soc/work-queue ───────────────────────────────────────

func TestSOCWorkQueue_IncludesAlertsWithHostname(t *testing.T) {
	pool := testPool(t)
	_, hostname, _ := seedAlertWithRule(t, pool, "queue")

	h := handlers.NewSOCQueueHandler(pool)
	code, resp := doJSON(t, http.MethodGet, "/api/v1/soc/work-queue", nil, h.WorkQueue)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %v)", code, resp)
	}
	if total := numField(t, resp, "total"); total == 0 {
		t.Fatalf("work queue が空: %v", resp)
	}

	// ホスト名が載っていないと SOC 担当が「どの端末か」を判断できない。
	if !responseContains(resp, hostname) {
		t.Errorf("work queue にホスト名 %q が出ていない: %v", hostname, resp)
	}
}

// ── /api/v1/soc/metrics (シフト引き継ぎ) ─────────────────────────

func TestSOCShiftHandover_TopAlertsCarryHostname(t *testing.T) {
	pool := testPool(t)
	agentID, hostname, _ := seedAlertWithRule(t, pool, "handover")

	// 引き継ぎのトップアラートは severity DESC, created_at ASC の上位 10 件。
	// 他のテストが残した severity 9 のアラートに押し出されないよう、
	// severity 10 かつ十分古い 1 件を入れて必ず先頭に来るようにする。
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO alerts (agent_id, severity, title, description, status, created_at)
		VALUES ($1::uuid, 10, 'alertcol-handover-top', 'd', 'open', NOW() - INTERVAL '365 days')`,
		agentID); err != nil {
		t.Fatalf("seed top alert: %v", err)
	}

	h := handlers.NewSOCMetricsHandler(pool)
	code, resp := doJSON(t, http.MethodGet, "/api/v1/soc/handover", nil, h.ShiftHandover)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %v)", code, resp)
	}
	if !responseContains(resp, hostname) {
		t.Errorf("引き継ぎのトップアラートにホスト名 %q が出ていない: %v", hostname, resp)
	}
}

// ── /api/v1/suppressions/candidates ──────────────────────────────

func TestSuppressionCandidates_GroupsByRuleNameAndHostname(t *testing.T) {
	pool := testPool(t)
	_, hostname, ruleName := seedAlertWithRule(t, pool, "cands")

	h := &handlers.SuppressionHandler{Pool: pool}
	// threshold=2 なら rules 由来 3 件・組み込み由来 2 件の両方が候補になる。
	code, resp := doJSON(t, http.MethodGet,
		"/api/v1/suppressions/candidates?days=1&threshold=2", nil, h.Candidates)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %v)", code, resp)
	}

	// rules に紐付くほうは rules.name で、紐付かないほうは title でまとまる。
	if !responseContains(resp, ruleName) {
		t.Errorf("候補に rules.name %q が出ていない: %v", ruleName, resp)
	}
	if !responseContains(resp, "alertcol-builtin-cands") {
		t.Errorf("rule_id 無しのアラートが title でまとまっていない: %v", resp)
	}
	if !responseContains(resp, hostname) {
		t.Errorf("候補にホスト名 %q が出ていない: %v", hostname, resp)
	}
}

// ── /api/v1/agents/:id/timeline ──────────────────────────────────

func TestAgentTimeline_IncludesAlerts(t *testing.T) {
	pool := testPool(t)
	agentID, _, ruleName := seedAlertWithRule(t, pool, "timeline")

	h := handlers.NewEventHandler(pool)
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/api/v1/agents/:id/timeline", h.AgentTimeline)

	w := jsonReq(r, http.MethodGet, "/api/v1/agents/"+agentID+"/timeline?hours=24", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, "alertcol-titled-timeline") {
		t.Errorf("タイムラインにアラートが出ていない: %s", body)
	}
	// ルールに紐付くアラートは副題にルール名が出る。
	if !strings.Contains(body, ruleName) {
		t.Errorf("タイムラインのアラート副題にルール名 %q が出ていない: %s", ruleName, body)
	}
}

// ── レポート生成 ─────────────────────────────────────────────────

func TestThreatSummary_PopulatesRulesTacticsAndTypes(t *testing.T) {
	pool := testPool(t)
	_, _, ruleName := seedAlertWithRule(t, pool, "report")

	g := reports.NewGenerator(pool)
	spec := &reports.ReportSpec{DateRange: reportRange()}

	data, err := g.GenerateThreatSummary(context.Background(), spec)
	if err != nil {
		t.Fatalf("GenerateThreatSummary: %v", err)
	}

	// 発火したルール一覧 (rule_id と対で出すので、rule_id 無しは載らない)。
	foundRule := false
	for _, r := range data.SigmaRulesHit {
		if r.RuleName == ruleName {
			foundRule = true
			if r.Hits != 3 {
				t.Errorf("%q の Hits = %d, want 3", ruleName, r.Hits)
			}
		}
	}
	if !foundRule {
		t.Errorf("SigmaRulesHit に %q が無い: %+v", ruleName, data.SigmaRulesHit)
	}

	// MITRE は mitre_technique をタクティクへ写して数える。
	// T1059 = execution / T1486 = impact なので 2 タクティクぶん出る。
	tactics := map[string]int{}
	for _, e := range data.MITRETactics {
		tactics[e.Tactic] = e.Count
	}
	if tactics["execution"] < 3 {
		t.Errorf("execution = %d, want >= 3 (T1059 を 3 件入れている): %+v", tactics["execution"], data.MITRETactics)
	}
	if tactics["impact"] < 2 {
		t.Errorf("impact = %d, want >= 2 (T1486 を 2 件入れている): %+v", tactics["impact"], data.MITRETactics)
	}

	// 種別内訳は source 列。sigma / anomaly の両方が出る。
	if data.ThreatsByType["sigma"] < 3 {
		t.Errorf("ThreatsByType[sigma] = %d, want >= 3: %+v", data.ThreatsByType["sigma"], data.ThreatsByType)
	}
	if data.ThreatsByType["anomaly"] < 2 {
		t.Errorf("ThreatsByType[anomaly] = %d, want >= 2: %+v", data.ThreatsByType["anomaly"], data.ThreatsByType)
	}
}

func TestExecutiveSummary_TopThreatsFallBackToTitle(t *testing.T) {
	pool := testPool(t)
	_, _, ruleName := seedAlertWithRule(t, pool, "exec")

	g := reports.NewGenerator(pool)
	spec := &reports.ReportSpec{DateRange: reportRange()}

	data, err := g.GenerateExecutiveSummary(context.Background(), spec)
	if err != nil {
		t.Fatalf("GenerateExecutiveSummary: %v", err)
	}

	names := map[string]int{}
	for _, e := range data.TopThreats {
		names[e.Name] = e.Count
	}
	// rules に紐付くものは rules.name、紐付かないものは title でまとまる。
	if names[ruleName] != 3 {
		t.Errorf("TopThreats[%q] = %d, want 3: %+v", ruleName, names[ruleName], data.TopThreats)
	}
	if names["alertcol-builtin-exec"] != 2 {
		t.Errorf("rule_id 無しのアラートが title でまとまっていない: %+v", data.TopThreats)
	}
}
