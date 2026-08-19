package handlers

import (
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// OpsReportHandler builds the operational report data for the frontend.
type OpsReportHandler struct {
	Pool *pgxpool.Pool
}

func NewOpsReportHandler(pool *pgxpool.Pool) *OpsReportHandler {
	return &OpsReportHandler{Pool: pool}
}

// GetReport returns a full operational report payload.
// GET /api/v1/reports/ops-report?days=30
func (h *OpsReportHandler) GetReport(c *gin.Context) {
	days, _ := strconv.Atoi(c.DefaultQuery("days", "30"))
	if days < 1 || days > 365 {
		days = 30
	}
	ctx := c.Request.Context()

	// ── Agents ──────────────────────────────────────────────────────────────
	var totalAgents, onlineAgents, offlineAgents, quarantineAgents int
	if h.Pool != nil {
		// 'inactive'(30日以上未確認で DeadAgentCleanup が退役扱いにした状態、
		// migration 315/330)は offline 側に寄せる。除外すると下の unreachable に
		// 落ち、退役ホストが「原因不明」として計上される。
		//
		// 'quarantine' は agents_status_check に存在しない値で、この FILTER は
		// 常に 0 を返していた。隔離状態の正しい値は 'isolated'。
		if !ReadOK(c, h.Pool.QueryRow(ctx, `
				SELECT
					COUNT(*),
					COUNT(*) FILTER (WHERE status = 'online'),
					COUNT(*) FILTER (WHERE status IN ('offline', 'inactive')),
					COUNT(*) FILTER (WHERE status = 'isolated')
				FROM agents`).Scan(&totalAgents, &onlineAgents, &offlineAgents, &quarantineAgents)) {
			return
		}
	}
	unreachable := totalAgents - onlineAgents - offlineAgents - quarantineAgents
	if unreachable < 0 {
		unreachable = 0
	}
	agentCoveragePct := 0.0
	if totalAgents > 0 {
		agentCoveragePct = math.Round(float64(onlineAgents)/float64(totalAgents)*1000) / 10
	}

	// ── Alerts ──────────────────────────────────────────────────────────────
	var totalAlerts, criticalAlerts, highAlerts, mediumAlerts, lowAlerts int
	var resolvedCritical, resolvedHigh, resolvedMedium, resolvedLow int
	if h.Pool != nil {
		if !ReadOK(c, h.Pool.QueryRow(ctx, fmt.Sprintf(`
				SELECT
					COUNT(*),
					COUNT(*) FILTER (WHERE severity >= 9),
					COUNT(*) FILTER (WHERE severity BETWEEN 7 AND 8),
					COUNT(*) FILTER (WHERE severity BETWEEN 4 AND 6),
					COUNT(*) FILTER (WHERE severity BETWEEN 1 AND 3),
					COUNT(*) FILTER (WHERE severity >= 9 AND status = 'resolved'),
					COUNT(*) FILTER (WHERE severity BETWEEN 7 AND 8 AND status = 'resolved'),
					COUNT(*) FILTER (WHERE severity BETWEEN 4 AND 6 AND status = 'resolved'),
					COUNT(*) FILTER (WHERE severity BETWEEN 1 AND 3 AND status = 'resolved')
				FROM alerts
				WHERE created_at >= NOW() - INTERVAL '%d days'`, days)).
			Scan(&totalAlerts, &criticalAlerts, &highAlerts, &mediumAlerts, &lowAlerts,
				&resolvedCritical, &resolvedHigh, &resolvedMedium, &resolvedLow)) {
			return
		}
	}

	alertStats := []gin.H{
		{
			"severity": "Critical (9-10)",
			"count":    criticalAlerts,
			"resolved": resolvedCritical,
			"pending":  criticalAlerts - resolvedCritical,
		},
		{
			"severity": "High (7-8)",
			"count":    highAlerts,
			"resolved": resolvedHigh,
			"pending":  highAlerts - resolvedHigh,
		},
		{
			"severity": "Medium (4-6)",
			"count":    mediumAlerts,
			"resolved": resolvedMedium,
			"pending":  mediumAlerts - resolvedMedium,
		},
		{
			"severity": "Low (1-3)",
			"count":    lowAlerts,
			"resolved": resolvedLow,
			"pending":  lowAlerts - resolvedLow,
		},
	}

	// ── Incidents ────────────────────────────────────────────────────────────
	var openIncidents, resolvedIncidents int
	type incRow struct {
		id, title, severity, status, createdAt string
		mttrMinutes                            *int
	}
	var incidents []incRow

	if h.Pool != nil {
		if !ReadOK(c, h.Pool.QueryRow(ctx, fmt.Sprintf(`
				SELECT
					COUNT(*) FILTER (WHERE status NOT IN ('resolved','closed')),
					COUNT(*) FILTER (WHERE status IN ('resolved','closed'))
				FROM incidents
				WHERE created_at >= NOW() - INTERVAL '%d days'`, days)).
			Scan(&openIncidents, &resolvedIncidents)) {
			return
		}

		rows, err := h.Pool.Query(ctx, fmt.Sprintf(`
			SELECT
				id::text,
				title,
				CASE
					WHEN severity >= 9 THEN 'critical'
					WHEN severity >= 7 THEN 'high'
					WHEN severity >= 4 THEN 'medium'
					ELSE 'low'
				END,
				status,
				to_char(created_at, 'YYYY-MM-DD'),
				CASE WHEN resolved_at IS NOT NULL
					THEN EXTRACT(EPOCH FROM (resolved_at - created_at))::int / 60
					ELSE NULL
				END
			FROM incidents
			WHERE created_at >= NOW() - INTERVAL '%d days'
			ORDER BY severity DESC, created_at DESC
			LIMIT 20`, days))
		if err == nil {
			for rows.Next() {
				var r incRow
				if rows.Scan(&r.id, &r.title, &r.severity, &r.status, &r.createdAt, &r.mttrMinutes) == nil {
					incidents = append(incidents, r)
				}
			}
			if err := rows.Err(); err != nil {
				slog.Warn("GetReport: rows の読み取りが途中で終わりました。この区画は不完全です", "error", err)
			}
			rows.Close()
		}
	}

	// ── MTTR ─────────────────────────────────────────────────────────────────
	var mttrMinutes float64
	if h.Pool != nil {
		if !ReadOK(c, h.Pool.QueryRow(ctx, fmt.Sprintf(`
				SELECT COALESCE(AVG(EXTRACT(EPOCH FROM (updated_at - created_at))/60), 0)
				FROM alerts
				WHERE status = 'resolved'
				  AND created_at >= NOW() - INTERVAL '%d days'`, days)).Scan(&mttrMinutes)) {
			return
		}
	}

	// ── Offline agents ────────────────────────────────────────────────────────
	type offlineAgent struct {
		hostname string
		lastSeen string
	}
	var offlineAgentList []offlineAgent
	if h.Pool != nil {
		rows, err := h.Pool.Query(ctx, `
			SELECT hostname, to_char(last_seen, 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
			FROM agents
			-- 上の offlineAgents 集計と同じ語彙に揃える。片方だけ 'inactive' を
			-- 含めると「N台オフライン」と一覧の件数が食い違う。
			WHERE status IN ('offline', 'inactive')
			ORDER BY last_seen DESC
			LIMIT 20`)
		if err == nil {
			for rows.Next() {
				var a offlineAgent
				if rows.Scan(&a.hostname, &a.lastSeen) == nil {
					offlineAgentList = append(offlineAgentList, a)
				}
			}
			if err := rows.Err(); err != nil {
				slog.Warn("GetReport: rows の読み取りが途中で終わりました。この区画は不完全です", "error", err)
			}
			rows.Close()
		}
	}

	// ── Threat Intel ──────────────────────────────────────────────────────────
	var iocCount, newThreats int
	if h.Pool != nil {
		if !ReadOK(c, h.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM ioc_entries WHERE is_active`).Scan(&iocCount)) {
			return
		}
		if !ReadOK(c, h.Pool.QueryRow(ctx, fmt.Sprintf(`
				SELECT COUNT(*) FROM ioc_entries
				WHERE created_at >= NOW() - INTERVAL '%d days'`, days)).Scan(&newThreats)) {
			return
		}
	}
	// Blocked = resolved alerts that matched IOC (proxy: critical+high resolved)
	blockedCount := resolvedCritical + resolvedHigh

	// ── Compliance ────────────────────────────────────────────────────────────
	var enabledRules, totalRules int
	var openCritical int
	var criticalVulns, highVulns int
	var totalIOC2 int
	if h.Pool != nil {
		if !ReadOK(c, h.Pool.QueryRow(ctx, `SELECT COUNT(*), COUNT(*) FILTER (WHERE enabled) FROM rules`).
			Scan(&totalRules, &enabledRules)) {
			return
		}
		if !ReadOK(c, h.Pool.QueryRow(ctx, `
				SELECT COUNT(*) FROM alerts
				WHERE severity >= 4 AND status NOT IN ('resolved','false_positive')`).Scan(&openCritical)) {
			return
		}
		if !ReadOK(c, h.Pool.QueryRow(ctx, `
				SELECT
					COUNT(*) FILTER (WHERE severity='critical' AND status='open'),
					COUNT(*) FILTER (WHERE severity='high' AND status='open')
				FROM vulnerabilities`).Scan(&criticalVulns, &highVulns)) {
			return
		}
		if !ReadOK(c, h.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM ioc_entries WHERE is_active`).Scan(&totalIOC2)) {
			return
		}
	}

	clamp := func(v int) int {
		if v < 0 {
			return 0
		}
		if v > 100 {
			return 100
		}
		return v
	}
	ruleScore := 0
	if totalRules > 0 {
		ruleScore = clamp(enabledRules * 100 / totalRules)
	}
	agentScore := clamp(int(agentCoveragePct))

	critAlertScore := 100
	switch {
	case openCritical > 20:
		critAlertScore = 10
	case openCritical > 10:
		critAlertScore = 30
	case openCritical > 5:
		critAlertScore = 60
	case openCritical > 0:
		critAlertScore = 80
	}
	vulnScore := 100
	switch {
	case criticalVulns > 10:
		vulnScore = 10
	case criticalVulns > 5:
		vulnScore = 30
	case criticalVulns > 0:
		vulnScore = 60
	case highVulns > 20:
		vulnScore = 70
	case highVulns > 0:
		vulnScore = 85
	}
	iocScore := 0
	switch {
	case totalIOC2 >= 100:
		iocScore = 100
	case totalIOC2 >= 50:
		iocScore = 80
	case totalIOC2 >= 10:
		iocScore = 50
	case totalIOC2 > 0:
		iocScore = 20
	}

	cisScore := clamp((ruleScore + agentScore) / 2)
	nistScore := clamp((agentScore + ruleScore + critAlertScore) / 3)
	mitreScore := clamp((ruleScore + iocScore) / 2)
	isoScore := clamp((agentScore + vulnScore) / 2)

	complianceStatus := func(s int) string {
		if s >= 80 {
			return "良好"
		}
		return "要改善"
	}

	compliance := []gin.H{
		{
			"framework":       "CIS Benchmark",
			"score":           cisScore,
			"controls_passed": cisScore * 2,
			"controls_total":  200,
			"status":          complianceStatus(cisScore),
		},
		{
			"framework":       "NIST CSF",
			"score":           nistScore,
			"controls_passed": nistScore * 2,
			"controls_total":  200,
			"status":          complianceStatus(nistScore),
		},
		{
			"framework":       "MITRE ATT&CK",
			"score":           mitreScore,
			"controls_passed": mitreScore * 15 / 10,
			"controls_total":  150,
			"status":          complianceStatus(mitreScore),
		},
		{
			"framework":       "ISO 27001",
			"score":           isoScore,
			"controls_passed": isoScore,
			"controls_total":  100,
			"status":          complianceStatus(isoScore),
		},
	}

	// ── Posture grade ─────────────────────────────────────────────────────────
	overallScore := (cisScore + nistScore + mitreScore + isoScore) / 4
	postureGrade := func(s int) string {
		switch {
		case s >= 90:
			return "A+"
		case s >= 80:
			return "A"
		case s >= 75:
			return "B+"
		case s >= 65:
			return "B"
		case s >= 55:
			return "C+"
		case s >= 45:
			return "C"
		default:
			return "D"
		}
	}(overallScore)

	// ── Recommendations ───────────────────────────────────────────────────────
	var recommendations []string
	if offlineAgents > 0 {
		recommendations = append(recommendations,
			fmt.Sprintf("%d台のオフラインエージェントを調査し、再接続または再インストールを実施してください", offlineAgents))
	}
	if criticalVulns > 0 {
		recommendations = append(recommendations,
			fmt.Sprintf("クリティカル脆弱性 %d件に対して緊急パッチ適用を推奨します", criticalVulns))
	}
	if highVulns > 0 {
		recommendations = append(recommendations,
			fmt.Sprintf("高リスク脆弱性 %d件のパッチ適用計画を策定してください", highVulns))
	}
	if openCritical > 0 {
		recommendations = append(recommendations,
			fmt.Sprintf("未解決のクリティカルアラート %d件を優先的に対応してください", openCritical))
	}
	if ruleScore < 80 {
		recommendations = append(recommendations, "検知ルールの有効化率が低下しています。無効ルールの見直しを推奨します")
	}
	if nistScore < 70 {
		recommendations = append(recommendations, "NIST CSFスコア向上のため、ネットワーク監視ルールの見直しを実施してください")
	}
	if mitreScore < 60 {
		recommendations = append(recommendations, "MITRE ATT&CK カバレッジ向上のため、脅威インテリジェンスの拡充を推奨します")
	}
	if len(recommendations) == 0 {
		recommendations = append(recommendations, "現在、重大な推奨事項はありません。継続的な監視を維持してください")
	}

	// ── Build response ────────────────────────────────────────────────────────
	agentStatusList := []gin.H{
		{"status": "オンライン", "count": onlineAgents},
		{"status": "オフライン", "count": offlineAgents},
		{"status": "未応答", "count": unreachable},
		{"status": "隔離", "count": quarantineAgents},
	}

	offlineOut := make([]gin.H, 0, len(offlineAgentList))
	for _, a := range offlineAgentList {
		offlineOut = append(offlineOut, gin.H{"hostname": a.hostname, "last_seen": a.lastSeen})
	}

	incidentsOut := make([]gin.H, 0, len(incidents))
	for _, r := range incidents {
		incidentsOut = append(incidentsOut, gin.H{
			"id":           r.id,
			"title":        r.title,
			"severity":     r.severity,
			"status":       r.status,
			"created_at":   r.createdAt,
			"mttr_minutes": r.mttrMinutes,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"metrics": gin.H{
			"total_incidents":    openIncidents + resolvedIncidents,
			"critical_alerts":    criticalAlerts,
			"agent_coverage_pct": agentCoveragePct,
			"open_incidents":     openIncidents,
			"resolved_incidents": resolvedIncidents,
			"mttr_minutes":       int(mttrMinutes),
			"posture_grade":      postureGrade,
		},
		"alert_stats":    alertStats,
		"incidents":      incidentsOut,
		"agent_statuses": agentStatusList,
		"offline_agents": offlineOut,
		"threat_intel": gin.H{
			"ioc_count":   iocCount,
			"new_threats": newThreats,
			"blocked":     blockedCount,
		},
		"compliance":      compliance,
		"recommendations": recommendations,
	})
}
