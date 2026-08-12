package handlers_test

// SOC KPI が重大度スケールを取り違えていた件の再発防止。
//
// alerts.severity は CHECK (1..10) だが、soc_metrics_handler は
// 1-4 スケール (4=クリティカル, 3=高, 2=中, 1=低) を前提に書かれていた。
// SQL としては通るためエラーにならず、数字だけが静かに間違っていた:
//
//   - 日次ボリュームの critical/high が常に 0 (severity=4 に一致しない)
//   - 重大度分布のラベルが 5 以上で空文字
//   - 引き継ぎの「クリティカル未対応」が常に 0
//   - ファネルの escalated が >= 3 で実質ほぼ全件
//   - SLA 判定が severity 5-8 のどの条件にも当たらず未達扱い
//   - 重大度別 MTTR が 4..1 のキーしか読まず常に 0
//
// しきい値は ops_report_handler / soar_handler と同じ
// >= 9 critical / >= 7 high / >= 4 medium。

import (
	"context"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/edr-platform/server/internal/api/handlers"
)

// seedSeverityAlerts は指定した重大度のアラートを n 件入れる。
// resolved=true なら解決済みにし、解決までの経過時間を分で与える。
func seedSeverityAlerts(t *testing.T, pool *pgxpool.Pool, agentID string,
	severity, n int, resolved bool, resolveMin int) {
	t.Helper()
	ctx := context.Background()

	status := "open"
	if resolved {
		status = "resolved"
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO alerts (agent_id, severity, title, description, status,
		                    created_at, updated_at)
		SELECT $1::uuid, $2, $3, 'd', $4,
		       NOW() - INTERVAL '1 hour' - make_interval(mins => $6),
		       NOW() - INTERVAL '1 hour'
		FROM generate_series(1, $5) g`,
		agentID, severity, "socsev-alert", status, n, resolveMin); err != nil {
		t.Fatalf("seed alerts (sev %d): %v", severity, err)
	}
}

// socSevAgent は専用エージェントを 1 台作り、後始末を登録する。
func socSevAgent(t *testing.T, pool *pgxpool.Pool, tag string) string {
	t.Helper()
	ctx := context.Background()

	var agentID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO agents (hostname, os_type, status, last_seen, enrolled_at)
		 VALUES ($1, 'linux', 'online', NOW(), NOW()) RETURNING id::text`,
		"socsev-"+tag).Scan(&agentID); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM agents WHERE id = $1`, agentID) })
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM alerts WHERE agent_id = $1`, agentID) })
	return agentID
}

// ── /api/v1/soc-metrics/summary ──────────────────────────────────

func TestSOCSummary_CountsTenPointSeverity(t *testing.T) {
	pool := testPool(t)
	agentID := socSevAgent(t, pool, "summary")

	// 9 = クリティカル, 8 = 高, 5 = 中, 2 = 低
	seedSeverityAlerts(t, pool, agentID, 9, 4, false, 0)
	seedSeverityAlerts(t, pool, agentID, 8, 3, false, 0)
	seedSeverityAlerts(t, pool, agentID, 5, 2, false, 0)
	seedSeverityAlerts(t, pool, agentID, 2, 1, false, 0)

	h := handlers.NewSOCMetricsHandler(pool)
	code, resp := doJSON(t, http.MethodGet,
		"/api/v1/soc-metrics/summary?days=30", nil, h.Summary)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %v)", code, resp)
	}

	// 日次ボリューム: critical は severity>=9、high は severity>=7。
	daily, _ := resp["daily_volume"].([]any)
	if len(daily) == 0 {
		t.Fatalf("日次ボリュームが空: %v", resp["daily_volume"])
	}
	var critTotal, highTotal float64
	for _, d := range daily {
		m, ok := d.(map[string]any)
		if !ok {
			continue
		}
		c, _ := m["critical"].(float64)
		hi, _ := m["high"].(float64)
		critTotal += c
		highTotal += hi
	}
	if critTotal < 4 {
		t.Errorf("critical 合計 = %v, want >= 4 (severity 9 を 4 件入れている)", critTotal)
	}
	// high は >= 7 なので 9 の 4 件 + 8 の 3 件。
	if highTotal < 7 {
		t.Errorf("high 合計 = %v, want >= 7 (severity 9 が 4 件 + 8 が 3 件)", highTotal)
	}

	// 重大度分布: 4 段階に丸め、ラベルが空にならないこと。
	dist, _ := resp["severity_dist"].([]any)
	if len(dist) == 0 {
		t.Fatalf("重大度分布が空: %v", resp["severity_dist"])
	}
	seenBands := map[float64]bool{}
	for _, d := range dist {
		m, ok := d.(map[string]any)
		if !ok {
			continue
		}
		sev, _ := m["severity"].(float64)
		label, _ := m["label"].(string)
		if label == "" {
			t.Errorf("severity %v のラベルが空 (以前は 5 以上で必ず空になっていた)", sev)
		}
		seenBands[sev] = true
	}
	for _, band := range []float64{9, 7, 4, 1} {
		if !seenBands[band] {
			t.Errorf("重大度帯 %v が出ていない: %v", band, dist)
		}
	}
}

// ── /api/v1/soc-metrics/handover ─────────────────────────────────

func TestSOCHandover_CountsCriticalOnTenPointScale(t *testing.T) {
	pool := testPool(t)
	agentID := socSevAgent(t, pool, "handover")

	seedSeverityAlerts(t, pool, agentID, 9, 3, false, 0)

	h := handlers.NewSOCMetricsHandler(pool)
	code, resp := doJSON(t, http.MethodGet,
		"/api/v1/soc-metrics/handover?hours=24", nil, h.ShiftHandover)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %v)", code, resp)
	}
	// 以前は severity=4 を数えていたため、実データでは常に 0 だった。
	if got := numField(t, resp, "critical_open"); got < 3 {
		t.Errorf("critical_open = %v, want >= 3", got)
	}
}

// ── /api/v1/soc/metrics (フロントエンド向け) ─────────────────────

func TestSOCFrontendMetrics_MTTRAndSLAUseTenPointScale(t *testing.T) {
	pool := testPool(t)
	agentID := socSevAgent(t, pool, "frontend")

	// クリティカル(9)を 30 分で解決 → SLA 目標 60 分に間に合っている。
	seedSeverityAlerts(t, pool, agentID, 9, 3, true, 30)
	// 高(8)を 120 分で解決 → 目標 240 分に間に合っている。
	seedSeverityAlerts(t, pool, agentID, 8, 2, true, 120)

	h := handlers.NewSOCMetricsHandler(pool)
	code, resp := doJSON(t, http.MethodGet, "/api/v1/soc/metrics", nil, h.FrontendMetrics)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %v)", code, resp)
	}

	// 重大度別 MTTR。以前はキーが 4..1 だったため、1-10 スケールの
	// 実データでは 1 件も一致せず全て 0 だった。
	mttr, _ := resp["mttr"].([]any)
	if len(mttr) != 4 {
		t.Fatalf("mttr の段数 = %d, want 4: %v", len(mttr), mttr)
	}
	byLabel := map[string]float64{}
	targets := map[string]float64{}
	for _, e := range mttr {
		m, ok := e.(map[string]any)
		if !ok {
			continue
		}
		label, _ := m["severity"].(string)
		cur, _ := m["current_min"].(float64)
		tgt, _ := m["target_min"].(float64)
		byLabel[label] = cur
		targets[label] = tgt
	}
	if byLabel["critical"] <= 0 {
		t.Errorf("critical の MTTR = %v, want > 0 (severity 9 を 3 件解決済みで入れている): %v", byLabel["critical"], mttr)
	}
	if byLabel["high"] <= 0 {
		t.Errorf("high の MTTR = %v, want > 0 (severity 8 を 2 件解決済みで入れている): %v", byLabel["high"], mttr)
	}
	// 目標値の対応が崩れていないこと。
	if targets["critical"] != 60 || targets["high"] != 240 {
		t.Errorf("MTTR 目標値がずれている: critical=%v high=%v", targets["critical"], targets["high"])
	}
}
