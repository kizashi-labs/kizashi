package handlers

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PredictiveAnalyticsHandler computes risk scores and trend data from the
// platform's own alert, event, and agent tables. No external ML service is
// required — scores are derived using statistical heuristics on real data.
type PredictiveAnalyticsHandler struct {
	pool *pgxpool.Pool
}

func NewPredictiveAnalyticsHandler(pool *pgxpool.Pool) *PredictiveAnalyticsHandler {
	return &PredictiveAnalyticsHandler{pool: pool}
}

// alerts.severity is a smallint scored 1–10, and the platform bands it as
// critical 9–10 / high 7–8 / medium 4–6 / low 1–3. That banding is the one used
// by ops_report_handler, soar_handler and every notification channel; it is
// written out here as SQL predicates because three of the statements in this
// file compared the column against the *labels* instead:
//
//	WHERE severity = 'high'                    -> 22P02 invalid input syntax for smallint
//	WHERE severity = 'medium'                  -> 22P02
//	FILTER (WHERE severity IN ('critical','high')) -> 22P02
//
// None of them could ever run. See the notes on fetchStats and GetTrends for
// what each one cost.
const (
	sevCritical = `severity >= 9`
	sevHigh     = `severity BETWEEN 7 AND 8`
	sevMedium   = `severity BETWEEN 4 AND 6`
	// sevHighOrAbove covers critical and high together (7–10).
	sevHighOrAbove = `severity >= 7`
)

// riskStats holds the raw counts used across multiple endpoints.
type riskStats struct {
	totalAgents    int
	offlineAgents  int
	criticalAlerts int
	highAlerts     int
	mediumAlerts   int
	totalAlerts7d  int
	totalAlerts30d int
	openIncidents  int
}

// fetchStats reads the counts every predictive endpoint is derived from.
//
// It returns an error when any read fails rather than reporting the zero value
// as a measurement. Two of these statements compared the smallint severity
// column against the strings 'high' and 'medium' and failed with 22P02 on every
// call, and because each row was scanned with `_ =` the failure was invisible:
// highAlerts and mediumAlerts were permanently 0. computeVulnRisk weights them
// 2 and 1 against critical's 4, so a fleet carrying 500 high-severity alerts and
// no criticals reported a vulnerability risk of exactly 0.00 — and
// GetRiskForecast extrapolated that 0 out to 90 days, listed "高優先度アラート数: 0"
// among its key drivers, and labelled the whole thing data_source "live".
//
// A count that could not be read is not a count of zero. Callers decide what to
// do with the difference; they may no longer be unable to see it.
func (h *PredictiveAnalyticsHandler) fetchStats(ctx context.Context) (riskStats, error) {
	var s riskStats
	if h.pool == nil {
		return s, fmt.Errorf("predictive: no database pool configured")
	}

	read := func(dest *int, name, sql string) error {
		if err := h.pool.QueryRow(ctx, sql).Scan(dest); err != nil {
			return fmt.Errorf("predictive: read %s: %w", name, err)
		}
		return nil
	}

	for _, q := range []struct {
		dest *int
		name string
		sql  string
	}{
		{&s.totalAgents, "total agents", `SELECT COUNT(*) FROM agents`},
		{&s.offlineAgents, "offline agents", `
			SELECT COUNT(*) FROM agents
			WHERE last_seen < NOW() - INTERVAL '10 minutes'`},

		// 重大度別アラート数（直近30日）
		{&s.criticalAlerts, "critical alerts", `
			SELECT COUNT(*) FROM alerts
			WHERE ` + sevCritical + ` AND created_at >= NOW() - INTERVAL '30 days'`},
		{&s.highAlerts, "high alerts", `
			SELECT COUNT(*) FROM alerts
			WHERE ` + sevHigh + ` AND created_at >= NOW() - INTERVAL '30 days'`},
		{&s.mediumAlerts, "medium alerts", `
			SELECT COUNT(*) FROM alerts
			WHERE ` + sevMedium + ` AND created_at >= NOW() - INTERVAL '30 days'`},

		// 直近7日・30日アラート総数
		{&s.totalAlerts7d, "alerts (7d)", `
			SELECT COUNT(*) FROM alerts WHERE created_at >= NOW() - INTERVAL '7 days'`},
		{&s.totalAlerts30d, "alerts (30d)", `
			SELECT COUNT(*) FROM alerts WHERE created_at >= NOW() - INTERVAL '30 days'`},
	} {
		if err := read(q.dest, q.name, q.sql); err != nil {
			return s, err
		}
	}

	// オープンインシデント（incidentsテーブルが存在する場合のみ）
	var hasIncidents bool
	if err := h.pool.QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM pg_tables WHERE schemaname='public' AND tablename='incidents')`,
	).Scan(&hasIncidents); err != nil {
		return s, fmt.Errorf("predictive: probe incidents table: %w", err)
	}
	if hasIncidents {
		if err := read(&s.openIncidents, "open incidents", `
			SELECT COUNT(*) FROM incidents WHERE status NOT IN ('resolved','closed')`); err != nil {
			return s, err
		}
	}

	return s, nil
}

// statsOrAbort reads the stats and, on failure, answers 503 and reports false.
// A predictive score derived from counts that could not be read is a number with
// nothing behind it, and these endpoints advertise data_source "live".
func (h *PredictiveAnalyticsHandler) statsOrAbort(c *gin.Context) (riskStats, bool) {
	s, err := h.fetchStats(c.Request.Context())
	if err != nil {
		slog.Error("predictive: risk statistics unavailable", "error", err)
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error":  "リスク統計を取得できませんでした",
			"detail": err.Error(),
		})
		return s, false
	}
	return s, true
}

// computeVulnRisk derives a 0–1 vulnerability risk score from alert distribution.
func computeVulnRisk(s riskStats) float64 {
	if s.totalAgents == 0 {
		return 0
	}
	// 重大アラートを高く重み付け
	weighted := float64(s.criticalAlerts*4+s.highAlerts*2+s.mediumAlerts) / float64(s.totalAgents)
	score := math.Min(1.0, weighted/10.0)
	return math.Round(score*100) / 100
}

// computeIncidentRisk derives an incident probability from trend data.
func computeIncidentRisk(s riskStats) float64 {
	if s.totalAlerts30d == 0 {
		return 0
	}
	// 直近7日のアラート密度と30日平均を比較
	avg30 := float64(s.totalAlerts30d) / 30.0
	avg7 := float64(s.totalAlerts7d) / 7.0
	trend := avg7 / math.Max(1.0, avg30)
	score := math.Min(1.0, (trend-1.0)*0.3+float64(s.openIncidents)*0.05)
	if score < 0 {
		score = 0
	}
	return math.Round(score*100) / 100
}

// computeAgentHealthRisk derives risk from offline agent ratio.
func computeAgentHealthRisk(s riskStats) float64 {
	if s.totalAgents == 0 {
		return 0
	}
	ratio := float64(s.offlineAgents) / float64(s.totalAgents)
	return math.Round(math.Min(1.0, ratio)*100) / 100
}

// GET /api/v1/admin/predictive/predictions
func (h *PredictiveAnalyticsHandler) ListPredictions(c *gin.Context) {
	s, ok := h.statsOrAbort(c)
	if !ok {
		return
	}
	now := time.Now()

	vulnRisk := computeVulnRisk(s)
	incidentRisk := computeIncidentRisk(s)
	agentRisk := computeAgentHealthRisk(s)

	vulnSeverity := "low"
	if vulnRisk >= 0.7 {
		vulnSeverity = "high"
	} else if vulnRisk >= 0.4 {
		vulnSeverity = "medium"
	}

	incidentSeverity := "low"
	if incidentRisk >= 0.6 {
		incidentSeverity = "high"
	} else if incidentRisk >= 0.3 {
		incidentSeverity = "medium"
	}

	predictions := []gin.H{
		{
			"id": "pred-vuln", "model_id": "model-vuln", "model_name": "脆弱性リスクモデル",
			"prediction_type": "vulnerability_risk", "target_entity": "endpoint",
			"predicted_value":    vulnRisk,
			"confidence_score":   0.80,
			"prediction_horizon": "7d",
			"predicted_at":       now,
			"valid_until":        now.Add(7 * 24 * time.Hour),
			"contributing_factors": []string{
				"重大アラート数: " + predictItoa(s.criticalAlerts),
				"高アラート数: " + predictItoa(s.highAlerts),
				"30日間アラート総数: " + predictItoa(s.totalAlerts30d),
			},
			"recommendation": vulnRecommendation(vulnRisk),
			"severity":       vulnSeverity,
		},
		{
			"id": "pred-incident", "model_id": "model-incident", "model_name": "インシデント発生モデル",
			"prediction_type": "incident_probability", "target_entity": "organization",
			"predicted_value":    incidentRisk,
			"confidence_score":   0.75,
			"prediction_horizon": "30d",
			"predicted_at":       now,
			"valid_until":        now.Add(30 * 24 * time.Hour),
			"contributing_factors": []string{
				"オープンインシデント数: " + predictItoa(s.openIncidents),
				"直近7日アラート数: " + predictItoa(s.totalAlerts7d),
				"30日平均との比較トレンド",
			},
			"recommendation": incidentRecommendation(incidentRisk),
			"severity":       incidentSeverity,
		},
		{
			"id": "pred-agent", "model_id": "model-agent", "model_name": "エージェント健全性モデル",
			"prediction_type": "agent_health_risk", "target_entity": "fleet",
			"predicted_value":    agentRisk,
			"confidence_score":   0.90,
			"prediction_horizon": "1d",
			"predicted_at":       now,
			"valid_until":        now.Add(24 * time.Hour),
			"contributing_factors": []string{
				"総エージェント数: " + predictItoa(s.totalAgents),
				"オフラインエージェント数: " + predictItoa(s.offlineAgents),
			},
			"recommendation": agentRecommendation(agentRisk),
			"severity":       agentSeverity(agentRisk),
		},
	}
	c.JSON(http.StatusOK, gin.H{"predictions": predictions, "total": len(predictions)})
}

// GET /api/v1/admin/predictive/models
func (h *PredictiveAnalyticsHandler) ListModels(c *gin.Context) {
	s, ok := h.statsOrAbort(c)
	if !ok {
		return
	}

	// データ量からモデルメタ情報を導出
	trainingSamples := s.totalAlerts30d * 365 // 年間推定
	if trainingSamples < 1000 {
		trainingSamples = 1000
	}

	models := []gin.H{
		{
			"id": "model-vuln", "name": "脆弱性リスクモデル", "version": "1.0.0",
			"algorithm": "weighted_heuristic", "status": "active",
			"description":      "アラート重大度の分布からリスクスコアを計算するヒューリスティックモデル",
			"feature_count":    3,
			"training_samples": trainingSamples,
			"last_trained":     time.Now().Truncate(24 * time.Hour),
			"next_retrain":     time.Now().Add(24 * time.Hour).Truncate(24 * time.Hour),
		},
		{
			"id": "model-incident", "name": "インシデント発生モデル", "version": "1.0.0",
			"algorithm": "trend_analysis", "status": "active",
			"description":      "アラートトレンドとオープンインシデント数からインシデント確率を算出",
			"feature_count":    3,
			"training_samples": trainingSamples,
			"last_trained":     time.Now().Truncate(24 * time.Hour),
			"next_retrain":     time.Now().Add(24 * time.Hour).Truncate(24 * time.Hour),
		},
		{
			"id": "model-agent", "name": "エージェント健全性モデル", "version": "1.0.0",
			"algorithm": "ratio_analysis", "status": "active",
			"description":      "オフラインエージェント率からフリートリスクを算出",
			"feature_count":    2,
			"training_samples": s.totalAgents * 30,
			"last_trained":     time.Now().Truncate(24 * time.Hour),
			"next_retrain":     time.Now().Add(24 * time.Hour).Truncate(24 * time.Hour),
		},
	}
	c.JSON(http.StatusOK, gin.H{"models": models, "total": len(models)})
}

// POST /api/v1/admin/predictive/models/:id/generate
func (h *PredictiveAnalyticsHandler) GeneratePredictions(c *gin.Context) {
	id := c.Param("id")
	s, ok := h.statsOrAbort(c)
	if !ok {
		return
	}

	baseRisk := computeVulnRisk(s)
	if id == "model-incident" {
		baseRisk = computeIncidentRisk(s)
	} else if id == "model-agent" {
		baseRisk = computeAgentHealthRisk(s)
	}

	horizon := 30
	values := make([]float64, horizon)
	// 線形トレンド予測（実データを基準にわずかな増加傾向を仮定）
	for i := 0; i < horizon; i++ {
		trend := float64(i) * 0.003
		values[i] = math.Round(math.Min(1.0, math.Max(0.0, baseRisk+trend))*1000) / 1000
	}

	peakDay := horizon - 1
	peakVal := values[peakDay]

	c.JSON(http.StatusOK, gin.H{
		"model_id":        id,
		"generated_at":    time.Now(),
		"horizon_days":    horizon,
		"forecast":        values,
		"peak_risk_day":   peakDay,
		"peak_risk_value": peakVal,
		"message":         "予測生成完了",
	})
}

// GET /api/v1/admin/predictive/trends
//
// NOT ROUTED. router.go registers predictions, predictions/generate, models,
// accuracy and risk-forecast under /admin/predictive; this path is not among
// them, so the handler is unreachable and its 22P02 never cost anything live.
// It is repaired rather than deleted because whether the trend endpoint should
// exist is a product question — but nothing here should be read as evidence
// that it works, because nothing has ever called it.
func (h *PredictiveAnalyticsHandler) GetTrends(c *gin.Context) {
	ctx := c.Request.Context()

	type dayRow struct {
		date         string
		alertCount   int
		anomalyCount int
	}

	// The anomaly filter compared the smallint severity column against the
	// strings 'critical' and 'high', so the whole statement failed with 22P02 on
	// every request. `if err == nil` then skipped the loop without logging, rows
	// stayed empty, and the 30-day loop below filled every single day from the
	// zero value of dayRow: 30 days of alert_count 0, anomaly_count 0, risk_score
	// 0.00 and patch_compliance 1.00. A flat, perfect month, indistinguishable
	// from a genuinely quiet one, on the strength of a query that never ran.
	//
	// A chart of thirty fabricated days is worse than no chart, so a failed read
	// is now an error rather than a shape.
	//
	// Reporting that error immediately exposed a second, independent reason this
	// endpoint could never have produced data: `DATE(created_at)` yields a date
	// (OID 1082) and the scan target is a string, which pgx rejects in binary
	// format. So even with the severity filter corrected, every row would have
	// been discarded by `_ = dbRows.Scan(...)` and the月 would still have come
	// out flat. The cast makes the column the text the row expects — and the
	// 'YYYY-MM-DD' it produces is exactly the key format dateMap is looked up
	// with below.
	if h.pool == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "トレンドを取得できませんでした"})
		return
	}
	var rows []dayRow
	dbRows, err := h.pool.Query(ctx, `
		SELECT
			DATE(created_at)::text AS day,
			COUNT(*) AS alert_count,
			COUNT(*) FILTER (WHERE `+sevHighOrAbove+`) AS anomaly_count
		FROM alerts
		WHERE created_at >= NOW() - INTERVAL '30 days'
		GROUP BY day
		ORDER BY day ASC`)
	if err != nil {
		slog.Error("predictive: trend query failed", "error", err)
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error":  "トレンドを取得できませんでした",
			"detail": err.Error(),
		})
		return
	}
	defer dbRows.Close()
	for dbRows.Next() {
		var r dayRow
		if err := dbRows.Scan(&r.date, &r.alertCount, &r.anomalyCount); err != nil {
			slog.Error("predictive: trend row scan failed", "error", err)
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error":  "トレンドを取得できませんでした",
				"detail": err.Error(),
			})
			return
		}
		rows = append(rows, r)
	}
	if err := dbRows.Err(); err != nil {
		slog.Error("predictive: trend row iteration failed", "error", err)
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error":  "トレンドを取得できませんでした",
			"detail": err.Error(),
		})
		return
	}

	// 30日分のマップを構築（データのない日は0）
	dateMap := make(map[string]dayRow)
	for _, r := range rows {
		dateMap[r.date] = r
	}

	now := time.Now()
	trends := make([]gin.H, 0, 30)
	totalAlerts := 0
	for _, r := range rows {
		totalAlerts += r.alertCount
	}
	avgAlerts := 1
	if len(rows) > 0 {
		avgAlerts = totalAlerts / len(rows)
		if avgAlerts < 1 {
			avgAlerts = 1
		}
	}

	for i := 29; i >= 0; i-- {
		day := now.AddDate(0, 0, -i)
		dateStr := day.Format("2006-01-02")
		r := dateMap[dateStr]

		// パッチコンプライアンスをアラート密度の逆数から推計
		compliance := math.Max(0.5, 1.0-float64(r.alertCount)/float64(avgAlerts*3))
		riskScore := math.Min(1.0, float64(r.anomalyCount*4+r.alertCount)/float64(avgAlerts*10))

		trends = append(trends, gin.H{
			"date":             dateStr,
			"risk_score":       math.Round(riskScore*100) / 100,
			"anomaly_count":    r.anomalyCount,
			"alert_count":      r.alertCount,
			"patch_compliance": math.Round(compliance*100) / 100,
		})
	}
	c.JSON(http.StatusOK, gin.H{"trends": trends})
}

// GetPredictions is an alias for ListPredictions.
func (h *PredictiveAnalyticsHandler) GetPredictions(c *gin.Context) {
	h.ListPredictions(c)
}

// GetModels is an alias for ListModels.
func (h *PredictiveAnalyticsHandler) GetModels(c *gin.Context) {
	h.ListModels(c)
}

// GET /api/v1/admin/predictive/accuracy
func (h *PredictiveAnalyticsHandler) GetAccuracyReport(c *gin.Context) {
	ctx := c.Request.Context()
	s, ok := h.statsOrAbort(c)
	if !ok {
		return
	}

	// アラート解決率を精度の代替指標として使用
	var resolvedAlerts, totalAlerts30d int
	for _, q := range []struct {
		dest *int
		sql  string
	}{
		{&totalAlerts30d, `
			SELECT COUNT(*) FROM alerts
			WHERE created_at >= NOW() - INTERVAL '30 days'`},
		{&resolvedAlerts, `
			SELECT COUNT(*) FROM alerts
			WHERE created_at >= NOW() - INTERVAL '30 days'
			  AND status IN ('resolved','closed')`},
	} {
		if err := h.pool.QueryRow(ctx, q.sql).Scan(q.dest); err != nil {
			slog.Error("predictive: accuracy report unavailable", "error", err)
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error":  "精度レポートを取得できませんでした",
				"detail": err.Error(),
			})
			return
		}
	}

	resolutionRate := 0.0
	if totalAlerts30d > 0 {
		resolutionRate = math.Round(float64(resolvedAlerts)/float64(totalAlerts30d)*1000) / 10
	}

	report := []gin.H{
		{
			"prediction_type": "vulnerability_risk",
			"total_alerts":    s.totalAlerts30d,
			"resolved_alerts": resolvedAlerts,
			"resolution_rate": resolutionRate,
			"note":            "アラート解決率を精度指標として使用",
		},
		{
			"prediction_type": "incident_probability",
			"open_incidents":  s.openIncidents,
			"note":            "インシデント追跡データに基づく",
		},
		{
			"prediction_type": "agent_health",
			"total_agents":    s.totalAgents,
			"offline_agents":  s.offlineAgents,
			"online_rate":     math.Round(float64(s.totalAgents-s.offlineAgents)/math.Max(1, float64(s.totalAgents))*1000) / 10,
		},
	}
	c.JSON(http.StatusOK, gin.H{"accuracy_report": report, "period_days": 30, "data_source": "live"})
}

// GET /api/v1/admin/predictive/risk-forecast
func (h *PredictiveAnalyticsHandler) GetRiskForecast(c *gin.Context) {
	s, ok := h.statsOrAbort(c)
	if !ok {
		return
	}

	current := computeVulnRisk(s)
	// 単純な線形外挿（実データ不足時は保守的な推定）
	predicted7d := math.Min(1.0, current+0.03)
	predicted30d := math.Min(1.0, current+0.08)
	predicted90d := math.Min(1.0, current+0.05) // 対策実施を想定してやや下がる

	trend := "stable"
	if predicted30d > current+0.05 {
		trend = "increasing"
	} else if predicted30d < current-0.05 {
		trend = "decreasing"
	}

	forecast := gin.H{
		"current_risk":  current,
		"predicted_7d":  math.Round(predicted7d*100) / 100,
		"predicted_30d": math.Round(predicted30d*100) / 100,
		"predicted_90d": math.Round(predicted90d*100) / 100,
		"trend":         trend,
		"key_drivers": []gin.H{
			{"factor": "重大アラート数", "count": s.criticalAlerts, "impact": math.Min(0.3, float64(s.criticalAlerts)*0.01)},
			{"factor": "高優先度アラート数", "count": s.highAlerts, "impact": math.Min(0.2, float64(s.highAlerts)*0.005)},
			{"factor": "オフラインエージェント", "count": s.offlineAgents, "impact": computeAgentHealthRisk(s) * 0.1},
		},
		"mitigations": []gin.H{
			{"action": "重大アラートの優先対応", "estimated_risk_reduction": 0.10},
			{"action": "オフラインエージェントの復旧", "estimated_risk_reduction": 0.05},
			{"action": "未解決インシデントのクローズ", "estimated_risk_reduction": 0.07},
		},
		"generated_at": time.Now(),
		"data_source":  "live",
	}
	c.JSON(http.StatusOK, forecast)
}

// ─── helpers ──────────────────────────────────────────────────────────────────

func predictItoa(n int) string {
	if n == 0 {
		return "0"
	}
	b := make([]byte, 0, 10)
	if n < 0 {
		b = append(b, '-')
		n = -n
	}
	var digits [10]byte
	pos := 10
	for n > 0 {
		pos--
		digits[pos] = byte('0' + n%10)
		n /= 10
	}
	return string(append(b, digits[pos:]...))
}

func vulnRecommendation(score float64) string {
	if score >= 0.7 {
		return "重大アラートを48時間以内に優先対応してください"
	} else if score >= 0.4 {
		return "高優先度アラートのトリアージを実施してください"
	}
	return "現在のセキュリティ体制を維持してください"
}

func incidentRecommendation(score float64) string {
	if score >= 0.6 {
		return "インシデント対応チームをアクティブ化し、アラート調査を強化してください"
	} else if score >= 0.3 {
		return "アラートトレンドを注視し、インシデント対応手順を確認してください"
	}
	return "定期的なアラートレビューを継続してください"
}

func agentRecommendation(score float64) string {
	if score >= 0.3 {
		return "オフラインエージェントの復旧を優先してください"
	} else if score >= 0.1 {
		return "オフラインエージェントの原因調査を行ってください"
	}
	return "エージェントフリートは正常です"
}

func agentSeverity(score float64) string {
	if score >= 0.3 {
		return "high"
	} else if score >= 0.1 {
		return "medium"
	}
	return "low"
}
