package handlers

import (
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// alerts.severity は CHECK (1..10) の数値列。
//
// このファイルはもともと 1-4 スケール (4=クリティカル, 3=高, 2=中, 1=低)
// を前提に書かれていたため、実データ (5/8/9 など) と噛み合わず
//
//   - 日次ボリュームの critical/high が常に 0
//   - 重大度分布のラベルが 5 以上で空
//   - 引き継ぎの「クリティカル未対応」が常に 0
//   - ファネルの escalated / エスカレーション率が実質「ほぼ全件」
//   - SLA 判定が severity 5-8 のどの条件にも当たらず未達扱い
//   - 重大度別 MTTR が 4..1 のキーしか読まず常に 0
//
// という状態だった。しきい値はコードベースの他所
// (ops_report_handler / soar_handler) と同じ >= 9 / >= 7 / >= 4 に揃える。

// sevBandSQL は severity を 4 段階の代表値 (9/7/4/1) に丸める SQL 式。
// GROUP BY の単位と、レスポンスに載せる severity の値を一致させるために使う。
const sevBandSQL = `CASE
	WHEN severity >= 9 THEN 9
	WHEN severity >= 7 THEN 7
	WHEN severity >= 4 THEN 4
	ELSE 1
END`

// sevBandLabel は代表値に対する日本語ラベル。
var sevBandLabel = map[int]string{9: "クリティカル", 7: "高", 4: "中", 1: "低"}

// SOCMetricsHandler provides SOC operational KPI endpoints.
type SOCMetricsHandler struct {
	Pool *pgxpool.Pool
}

func NewSOCMetricsHandler(pool *pgxpool.Pool) *SOCMetricsHandler {
	return &SOCMetricsHandler{Pool: pool}
}

// Summary returns SOC KPIs: MTTD, MTTR, volume trends, analyst productivity.
// GET /api/v1/soc-metrics/summary?days=30
func (h *SOCMetricsHandler) Summary(c *gin.Context) {
	days, _ := strconv.Atoi(c.DefaultQuery("days", "30"))
	if days < 1 || days > 365 {
		days = 30
	}
	ctx := c.Request.Context()

	type DailyVolume struct {
		Date     string `json:"date"`
		Total    int    `json:"total"`
		Critical int    `json:"critical"`
		High     int    `json:"high"`
		Resolved int    `json:"resolved"`
	}

	type SeverityDist struct {
		Severity int    `json:"severity"`
		Label    string `json:"label"`
		Count    int    `json:"count"`
		Pct      int    `json:"pct"`
	}

	type AnalystStat struct {
		UserID   string  `json:"user_id"`
		Name     string  `json:"name"`
		Resolved int     `json:"resolved"`
		AvgHrs   float64 `json:"avg_hours"`
	}

	var (
		totalAlerts, openAlerts, resolvedAlerts int
		mttdHrs, mttrHrs                        float64
		falsePositiveRate                       float64
		dailyVolume                             []DailyVolume
		severityDist                            []SeverityDist
		analystStats                            []AnalystStat
		resolvedToday, createdToday             int
	)

	if h.Pool == nil {
		c.JSON(http.StatusOK, gin.H{
			"mttd_hours": 0, "mttr_hours": 0,
			"total_alerts": 0, "open_alerts": 0,
			"false_positive_rate": 0,
			"daily_volume":        []DailyVolume{},
			"severity_dist":       []SeverityDist{},
			"analyst_stats":       []AnalystStat{},
		})
		return
	}

	// ── Core KPIs ─────────────────────────────────────────
	_ = h.Pool.QueryRow(ctx, fmt.Sprintf(`
		SELECT
			COUNT(*) AS total,
			COUNT(*) FILTER (WHERE status NOT IN ('resolved','false_positive')) AS open,
			COUNT(*) FILTER (WHERE status = 'resolved') AS resolved
		FROM alerts
		WHERE created_at >= NOW() - INTERVAL '%d days'`, days)).
		Scan(&totalAlerts, &openAlerts, &resolvedAlerts)

	// MTTR: time from alert creation to first 'resolved' status change (accurate)
	_ = h.Pool.QueryRow(ctx, fmt.Sprintf(`
		SELECT COALESCE(AVG(
			EXTRACT(EPOCH FROM (asc2.changed_at - a.created_at)) / 3600
		), 0)
		FROM alerts a
		JOIN (
			SELECT DISTINCT ON (alert_id) alert_id, changed_at
			FROM alert_status_changes
			WHERE to_status = 'resolved'
			ORDER BY alert_id, changed_at ASC
		) asc2 ON asc2.alert_id = a.id
		WHERE a.created_at >= NOW() - INTERVAL '%d days'`, days)).Scan(&mttrHrs)

	// MTTD: time from alert creation to first triage ('investigating' or 'in_progress' status)
	_ = h.Pool.QueryRow(ctx, fmt.Sprintf(`
		SELECT COALESCE(AVG(
			EXTRACT(EPOCH FROM (asc2.changed_at - a.created_at)) / 3600
		), 0)
		FROM alerts a
		JOIN (
			SELECT DISTINCT ON (alert_id) alert_id, changed_at
			FROM alert_status_changes
			WHERE to_status IN ('investigating', 'in_progress')
			ORDER BY alert_id, changed_at ASC
		) asc2 ON asc2.alert_id = a.id
		WHERE a.created_at >= NOW() - INTERVAL '%d days'`, days)).Scan(&mttdHrs)

	// False positive rate
	var fpCount int
	_ = h.Pool.QueryRow(ctx, fmt.Sprintf(`
		SELECT COUNT(*) FROM alerts
		WHERE created_at >= NOW() - INTERVAL '%d days'
		  AND status = 'false_positive'`, days)).Scan(&fpCount)
	if totalAlerts > 0 {
		falsePositiveRate = float64(fpCount) / float64(totalAlerts) * 100
	}

	// Today stats
	_ = h.Pool.QueryRow(ctx, `
		SELECT
			COUNT(*) FILTER (WHERE status='resolved' AND DATE(updated_at) = CURRENT_DATE),
			COUNT(*) FILTER (WHERE DATE(created_at) = CURRENT_DATE)
		FROM alerts`).Scan(&resolvedToday, &createdToday)

	// ── Daily volume (last N days) ──────────────────────────
	rows, err := h.Pool.Query(ctx, fmt.Sprintf(`
		SELECT
			to_char(DATE(created_at), 'YYYY-MM-DD') AS day,
			COUNT(*) AS total,
			COUNT(*) FILTER (WHERE severity >= 9) AS critical,
			COUNT(*) FILTER (WHERE severity >= 7) AS high,
			COUNT(*) FILTER (WHERE status='resolved') AS resolved
		FROM alerts
		WHERE created_at >= NOW() - INTERVAL '%d days'
		GROUP BY 1 ORDER BY 1`, days))
	if err == nil {
		for rows.Next() {
			var d DailyVolume
			if err := rows.Scan(&d.Date, &d.Total, &d.Critical, &d.High, &d.Resolved); err == nil {
				dailyVolume = append(dailyVolume, d)
			}
		}
		if err := rows.Err(); err != nil {
			slog.Warn("row iteration error", "error", err)
		}
		rows.Close()
	}

	// ── Severity distribution ───────────────────────────────
	rows2, err := h.Pool.Query(ctx, fmt.Sprintf(`
		SELECT %s AS band, COUNT(*) AS cnt
		FROM alerts
		WHERE created_at >= NOW() - INTERVAL '%d days'
		GROUP BY 1 ORDER BY 1 DESC`, sevBandSQL, days))
	if err == nil {
		for rows2.Next() {
			var sev, cnt int
			if err := rows2.Scan(&sev, &cnt); err == nil {
				pct := 0
				if totalAlerts > 0 {
					pct = cnt * 100 / totalAlerts
				}
				severityDist = append(severityDist, SeverityDist{
					Severity: sev, Label: sevBandLabel[sev], Count: cnt, Pct: pct,
				})
			}
		}
		if err := rows2.Err(); err != nil {
			slog.Warn("row iteration error", "error", err)
		}
		rows2.Close()
	}

	// ── Analyst productivity ────────────────────────────────
	rows3, err := h.Pool.Query(ctx, fmt.Sprintf(`
		SELECT
			COALESCE(a.assigned_to::text, ''),
			COALESCE(u.display_name, u.username, 'Unknown'),
			COUNT(*) FILTER (WHERE a.status='resolved') AS resolved,
			COALESCE(AVG(EXTRACT(EPOCH FROM (a.updated_at - a.created_at))/3600) FILTER (WHERE a.status='resolved'), 0)
		FROM alerts a
		LEFT JOIN users u ON u.id::text = a.assigned_to::text
		WHERE a.created_at >= NOW() - INTERVAL '%d days'
		  AND a.assigned_to IS NOT NULL
		GROUP BY 1, 2
		ORDER BY 3 DESC
		LIMIT 10`, days))
	if err == nil {
		for rows3.Next() {
			var s AnalystStat
			if err := rows3.Scan(&s.UserID, &s.Name, &s.Resolved, &s.AvgHrs); err == nil {
				analystStats = append(analystStats, s)
			}
		}
		if err := rows3.Err(); err != nil {
			slog.Warn("row iteration error", "error", err)
		}
		rows3.Close()
	}

	if dailyVolume == nil {
		dailyVolume = []DailyVolume{}
	}
	if severityDist == nil {
		severityDist = []SeverityDist{}
	}
	if analystStats == nil {
		analystStats = []AnalystStat{}
	}

	c.JSON(http.StatusOK, gin.H{
		"days":                 days,
		"total_alerts":         totalAlerts,
		"open_alerts":          openAlerts,
		"resolved_alerts":      resolvedAlerts,
		"false_positive_count": fpCount,
		"false_positive_rate":  falsePositiveRate,
		"mttd_hours":           mttdHrs,
		"mttr_hours":           mttrHrs,
		"resolved_today":       resolvedToday,
		"created_today":        createdToday,
		"daily_volume":         dailyVolume,
		"severity_dist":        severityDist,
		"analyst_stats":        analystStats,
	})
}

// ShiftHandover returns a summary for SOC shift handover (last 8 or 12 hours).
// GET /api/v1/soc-metrics/handover?hours=8
func (h *SOCMetricsHandler) ShiftHandover(c *gin.Context) {
	hours, _ := strconv.Atoi(c.DefaultQuery("hours", "8"))
	if hours < 1 || hours > 24 {
		hours = 8
	}
	ctx := c.Request.Context()

	type AlertSummary struct {
		ID       string `json:"id"`
		Title    string `json:"title"`
		Severity int    `json:"severity"`
		Status   string `json:"status"`
		Hostname string `json:"hostname"`
		Age      string `json:"created_at"`
	}

	var newCount, resolvedCount, critCount int
	var topAlerts []AlertSummary

	if h.Pool != nil {
		_ = h.Pool.QueryRow(ctx, fmt.Sprintf(`
			SELECT
				COUNT(*) FILTER (WHERE created_at >= NOW()-INTERVAL '%d hours') AS new,
				COUNT(*) FILTER (WHERE status='resolved' AND updated_at >= NOW()-INTERVAL '%d hours') AS resolved,
				COUNT(*) FILTER (WHERE severity >= 9 AND status NOT IN ('resolved','false_positive')) AS crit
			FROM alerts`, hours, hours)).Scan(&newCount, &resolvedCount, &critCount)

		// alerts に agent_hostname 列は無い。ホスト名は agents から JOIN で引く。
		rows, err := h.Pool.Query(ctx, `
			SELECT al.id::text, al.title, al.severity, al.status,
			       COALESCE(ag.hostname,''), al.created_at::text
			FROM alerts al
			LEFT JOIN agents ag ON ag.id = al.agent_id
			WHERE al.status NOT IN ('resolved','false_positive')
			  AND al.severity >= 4
			ORDER BY al.severity DESC, al.created_at ASC
			LIMIT 10`)
		if err != nil {
			slog.Warn("soc_metrics: top alerts query failed", "error", err)
		}
		if rows != nil {
			for rows.Next() {
				var a AlertSummary
				if err := rows.Scan(&a.ID, &a.Title, &a.Severity, &a.Status, &a.Hostname, &a.Age); err == nil {
					topAlerts = append(topAlerts, a)
				}
			}
			if err := rows.Err(); err != nil {
				slog.Warn("row iteration error", "error", err)
			}
			rows.Close()
		}
	}

	if topAlerts == nil {
		topAlerts = []AlertSummary{}
	}

	c.JSON(http.StatusOK, gin.H{
		"hours":          hours,
		"new_alerts":     newCount,
		"resolved":       resolvedCount,
		"critical_open":  critCount,
		"pending_alerts": topAlerts,
	})
}

// FrontendMetrics returns SOC KPIs in the shape expected by the /soc/metrics frontend page.
// GET /api/v1/soc/metrics?period=today|week|month
func (h *SOCMetricsHandler) FrontendMetrics(c *gin.Context) {
	period := c.DefaultQuery("period", "month")
	var days int
	switch period {
	case "today":
		days = 1
	case "week":
		days = 7
	default:
		days = 30
	}
	ctx := c.Request.Context()

	type analystDBRow struct {
		id              string
		name            string
		alertsHandled   int
		avgTriageMin    float64
		escalationRate  float64
		fpRate          float64
		currentWorkload int
	}
	type categoryRow struct {
		name           string
		volume         int
		avgTriageMin   float64
		escalationRate float64
	}
	type incidentRow struct {
		id         string
		title      string
		severity   string
		ageHours   int
		assignedTo string
	}

	var (
		funnelTotal, funnelTriaged, funnelEscalated, funnelResolved, funnelIncidents int
		totalResolved, withinSLA                                                     int
		slaCompliance                                                                float64
		resAutoCount, resAnalystCount, resFpCount, resEscCount                       int
		analystRows                                                                  []analystDBRow
		ageBuckets                                                                   []gin.H
		categories                                                                   []categoryRow
		mttrCurrent, mttrPrev                                                        map[int]float64
		openIncidents                                                                []incidentRow
	)

	mttrCurrent = make(map[int]float64)
	mttrPrev = make(map[int]float64)

	if h.Pool != nil {
		// ── Funnel ──────────────────────────────────────────────────────────
		_ = h.Pool.QueryRow(ctx, fmt.Sprintf(`
			SELECT
				COUNT(*)                                                AS total,
				COUNT(*) FILTER (WHERE status != 'open')               AS triaged,
				COUNT(*) FILTER (WHERE severity >= 7)                  AS escalated,
				COUNT(*) FILTER (WHERE status = 'resolved')            AS resolved
			FROM alerts
			WHERE created_at >= NOW() - INTERVAL '%d days'`, days)).
			Scan(&funnelTotal, &funnelTriaged, &funnelEscalated, &funnelResolved)
		_ = h.Pool.QueryRow(ctx, fmt.Sprintf(`
			SELECT COUNT(*) FROM incidents
			WHERE created_at >= NOW() - INTERVAL '%d days'`, days)).Scan(&funnelIncidents)

		// ── Analysts ────────────────────────────────────────────────────────
		rows, err := h.Pool.Query(ctx, fmt.Sprintf(`
			SELECT
				COALESCE(a.assigned_to::text, ''),
				COALESCE(u.display_name, u.username, 'Unknown'),
				COUNT(*) FILTER (WHERE a.status = 'resolved')                               AS handled,
				COALESCE(AVG(EXTRACT(EPOCH FROM (a.updated_at - a.created_at))/60)
				         FILTER (WHERE a.status = 'resolved'), 0)                           AS avg_min,
				COALESCE(COUNT(*) FILTER (WHERE a.severity >= 7)::float8
				         / NULLIF(COUNT(*), 0) * 100, 0)                                    AS esc_rate,
				COALESCE(COUNT(*) FILTER (WHERE a.status = 'false_positive')::float8
				         / NULLIF(COUNT(*), 0) * 100, 0)                                    AS fp_rate,
				COUNT(*) FILTER (WHERE a.status IN ('open','investigating'))                AS workload
			FROM alerts a
			LEFT JOIN users u ON u.id = a.assigned_to
			WHERE a.created_at >= NOW() - INTERVAL '%d days'
			  AND a.assigned_to IS NOT NULL
			GROUP BY a.assigned_to, u.display_name, u.username
			ORDER BY handled DESC
			LIMIT 10`, days))
		if err == nil {
			for rows.Next() {
				var r analystDBRow
				if e := rows.Scan(&r.id, &r.name, &r.alertsHandled, &r.avgTriageMin,
					&r.escalationRate, &r.fpRate, &r.currentWorkload); e == nil {
					analystRows = append(analystRows, r)
				}
			}
			if e := rows.Err(); e != nil {
				slog.Warn("soc analysts scan", "error", e)
			}
			rows.Close()
		}

		// ── Alert age buckets ────────────────────────────────────────────────
		bucketLabels := []string{"0-1時間", "1-4時間", "4-8時間", "8-24時間", "24時間以上"}
		bucketMap := make(map[string]int)
		rows2, err := h.Pool.Query(ctx, `
			SELECT
				CASE
					WHEN EXTRACT(EPOCH FROM (NOW()-created_at))/3600 < 1  THEN '0-1時間'
					WHEN EXTRACT(EPOCH FROM (NOW()-created_at))/3600 < 4  THEN '1-4時間'
					WHEN EXTRACT(EPOCH FROM (NOW()-created_at))/3600 < 8  THEN '4-8時間'
					WHEN EXTRACT(EPOCH FROM (NOW()-created_at))/3600 < 24 THEN '8-24時間'
					ELSE '24時間以上'
				END AS bucket,
				COUNT(*) AS cnt
			FROM alerts
			WHERE status NOT IN ('resolved','false_positive')
			GROUP BY 1`)
		if err == nil {
			for rows2.Next() {
				var lbl string
				var cnt int
				if rows2.Scan(&lbl, &cnt) == nil {
					bucketMap[lbl] = cnt
				}
			}
			rows2.Close()
		}
		for _, lbl := range bucketLabels {
			ageBuckets = append(ageBuckets, gin.H{"label": lbl, "count": bucketMap[lbl]})
		}

		// ── SLA compliance ───────────────────────────────────────────────────
		_ = h.Pool.QueryRow(ctx, fmt.Sprintf(`
			SELECT COUNT(*),
				COUNT(*) FILTER (WHERE
					(severity >= 9 AND EXTRACT(EPOCH FROM (updated_at-created_at))/60 <= 60) OR
					(severity BETWEEN 7 AND 8 AND EXTRACT(EPOCH FROM (updated_at-created_at))/60 <= 240) OR
					(severity BETWEEN 4 AND 6 AND EXTRACT(EPOCH FROM (updated_at-created_at))/60 <= 480) OR
					(severity <= 3 AND EXTRACT(EPOCH FROM (updated_at-created_at))/60 <= 2880)
				)
			FROM alerts
			WHERE status = 'resolved'
			  AND created_at >= NOW() - INTERVAL '%d days'`, days)).
			Scan(&totalResolved, &withinSLA)
		if totalResolved > 0 {
			slaCompliance = math.Round(float64(withinSLA)/float64(totalResolved)*1000) / 10
		}

		// ── Alert categories ─────────────────────────────────────────────────
		rows3, err := h.Pool.Query(ctx, fmt.Sprintf(`
			SELECT
				CASE
					WHEN lower(title) LIKE '%%ransomware%%' OR lower(title) LIKE '%%ランサム%%' THEN 'ランサムウェア'
					WHEN lower(title) LIKE '%%malware%%'   OR lower(title) LIKE '%%マルウェア%%' THEN 'マルウェア検知'
					WHEN lower(title) LIKE '%%phish%%'     OR lower(title) LIKE '%%フィッシング%%' THEN 'フィッシング'
					WHEN lower(title) LIKE '%%privilege%%' OR lower(title) LIKE '%%昇格%%' OR lower(title) LIKE '%%escalat%%' THEN '特権昇格'
					WHEN lower(title) LIKE '%%process%%'   OR lower(title) LIKE '%%プロセス%%' THEN '不審なプロセス'
					WHEN lower(title) LIKE '%%network%%'   OR lower(title) LIKE '%%ネットワーク%%' OR lower(title) LIKE '%%dns%%' THEN 'ネットワーク異常'
					WHEN lower(title) LIKE '%%auth%%'      OR lower(title) LIKE '%%login%%' OR lower(title) LIKE '%%logon%%' OR lower(title) LIKE '%%認証%%' THEN '認証失敗'
					WHEN lower(title) LIKE '%%data%%'      OR lower(title) LIKE '%%exfil%%' OR lower(title) LIKE '%%漏洩%%' THEN 'データ漏洩'
					ELSE 'その他'
				END AS cat,
				COUNT(*) AS volume,
				COALESCE(AVG(EXTRACT(EPOCH FROM (updated_at-created_at))/60)
				         FILTER (WHERE status='resolved'), 0)                          AS avg_min,
				COALESCE(COUNT(*) FILTER (WHERE severity >= 7)::float8
				         / NULLIF(COUNT(*),0) * 100, 0)                                AS esc_rate
			FROM alerts
			WHERE created_at >= NOW() - INTERVAL '%d days'
			GROUP BY 1
			ORDER BY volume DESC
			LIMIT 8`, days))
		if err == nil {
			for rows3.Next() {
				var r categoryRow
				if rows3.Scan(&r.name, &r.volume, &r.avgTriageMin, &r.escalationRate) == nil {
					categories = append(categories, r)
				}
			}
			rows3.Close()
		}

		// ── MTTR current period ──────────────────────────────────────────────
		rows4, err := h.Pool.Query(ctx, fmt.Sprintf(`
			SELECT %s AS band,
				COALESCE(AVG(EXTRACT(EPOCH FROM (updated_at-created_at))/60), 0)
			FROM alerts
			WHERE status = 'resolved'
			  AND created_at >= NOW() - INTERVAL '%d days'
			GROUP BY 1`, sevBandSQL, days))
		if err == nil {
			for rows4.Next() {
				var sev int
				var avg float64
				if rows4.Scan(&sev, &avg) == nil {
					mttrCurrent[sev] = avg
				}
			}
			rows4.Close()
		}
		// MTTR previous 30d (for comparison)
		rows5, err := h.Pool.Query(ctx, `
			SELECT `+sevBandSQL+` AS band,
				COALESCE(AVG(EXTRACT(EPOCH FROM (updated_at-created_at))/60), 0)
			FROM alerts
			WHERE status = 'resolved'
			  AND created_at BETWEEN NOW()-INTERVAL '60 days' AND NOW()-INTERVAL '30 days'
			GROUP BY 1`)
		if err == nil {
			for rows5.Next() {
				var sev int
				var avg float64
				if rows5.Scan(&sev, &avg) == nil {
					mttrPrev[sev] = avg
				}
			}
			rows5.Close()
		}

		// ── Open incidents ───────────────────────────────────────────────────
		rows6, err := h.Pool.Query(ctx, `
			SELECT
				i.id::text,
				i.title,
				CASE
					WHEN i.severity >= 8 THEN 'critical'
					WHEN i.severity >= 6 THEN 'high'
					WHEN i.severity >= 4 THEN 'medium'
					ELSE 'low'
				END,
				EXTRACT(EPOCH FROM (NOW()-i.created_at))/3600,
				COALESCE(u.display_name, u.username, '未割当')
			FROM incidents i
			LEFT JOIN users u ON u.id = i.assigned_to
			WHERE i.status NOT IN ('resolved','closed')
			ORDER BY i.severity DESC, i.created_at ASC
			LIMIT 10`)
		if err == nil {
			for rows6.Next() {
				var r incidentRow
				var ageF float64
				if rows6.Scan(&r.id, &r.title, &r.severity, &ageF, &r.assignedTo) == nil {
					r.ageHours = int(ageF)
					openIncidents = append(openIncidents, r)
				}
			}
			rows6.Close()
		}

		// ── Resolution methods ───────────────────────────────────────────────
		_ = h.Pool.QueryRow(ctx, fmt.Sprintf(`
			SELECT
				COUNT(*) FILTER (WHERE status = 'auto_resolved')                            AS auto_res,
				COUNT(*) FILTER (WHERE status = 'resolved' AND assigned_to IS NOT NULL)     AS analyst,
				COUNT(*) FILTER (WHERE status = 'false_positive')                           AS fp,
				(SELECT COUNT(DISTINCT ia.alert_id)
				 FROM incident_alerts ia
				 JOIN alerts a2 ON a2.id::text = ia.alert_id
				 WHERE a2.created_at >= NOW() - INTERVAL '%d days'
				   AND a2.status IN ('resolved','auto_resolved'))                           AS escalated
			FROM alerts
			WHERE created_at >= NOW() - INTERVAL '%d days'`, days, days)).
			Scan(&resAutoCount, &resAnalystCount, &resFpCount, &resEscCount)
		// Unassigned resolved goes to auto bucket
		_ = h.Pool.QueryRow(ctx, fmt.Sprintf(`
			SELECT COUNT(*) FILTER (WHERE status = 'resolved' AND assigned_to IS NULL)
			FROM alerts WHERE created_at >= NOW() - INTERVAL '%d days'`, days)).
			Scan(new(int)) // capture into auto bucket below
		var resUnassigned int
		_ = h.Pool.QueryRow(ctx, fmt.Sprintf(`
			SELECT COUNT(*) FROM alerts
			WHERE created_at >= NOW() - INTERVAL '%d days'
			  AND status = 'resolved' AND assigned_to IS NULL`, days)).Scan(&resUnassigned)
		resAutoCount += resUnassigned
	}

	// ── Build analyst output ─────────────────────────────────────────────────
	analystColors := []string{"#e8002d", "#3b82f6", "#10b981", "#f59e0b", "#8b5cf6", "#06b6d4", "#f97316", "#ec4899"}
	analysts := make([]gin.H, 0, len(analystRows))
	for i, r := range analystRows {
		parts := strings.Fields(r.name)
		initials := ""
		for _, p := range parts {
			runes := []rune(p)
			if len(runes) > 0 {
				initials += string(runes[0])
			}
		}
		if len([]rune(initials)) > 2 {
			initials = string([]rune(initials)[:2])
		}
		tier := "L1"
		if r.alertsHandled >= 200 {
			tier = "L3"
		} else if r.alertsHandled >= 80 {
			tier = "L2"
		}
		analysts = append(analysts, gin.H{
			"id":               r.id,
			"name":             r.name,
			"initials":         initials,
			"tier":             tier,
			"alerts_handled":   r.alertsHandled,
			"avg_triage_min":   math.Round(r.avgTriageMin*10) / 10,
			"escalation_rate":  math.Round(r.escalationRate*10) / 10,
			"fp_rate":          math.Round(r.fpRate*10) / 10,
			"satisfaction":     4.2,
			"current_workload": r.currentWorkload,
			"color":            analystColors[i%len(analystColors)],
		})
	}

	// ── Build MTTR output ────────────────────────────────────────────────────
	// キーは sevBandSQL が返す代表値 (9/7/4/1)。以前は 4..1 を読んでいたため、
	// 1-10 スケールの実データでは 1 件も一致せず MTTR が常に 0 だった。
	mttrTargets := map[int]int{9: 60, 7: 240, 4: 480, 1: 2880}
	mttrLabels := map[int]string{9: "critical", 7: "high", 4: "medium", 1: "low"}
	mttrOut := make([]gin.H, 0, 4)
	for _, sev := range []int{9, 7, 4, 1} {
		mttrOut = append(mttrOut, gin.H{
			"severity":       mttrLabels[sev],
			"current_min":    int(mttrCurrent[sev]),
			"target_min":     mttrTargets[sev],
			"last_month_min": int(mttrPrev[sev]),
		})
	}

	// ── Build categories output ──────────────────────────────────────────────
	catsOut := make([]gin.H, 0, len(categories))
	for _, r := range categories {
		catsOut = append(catsOut, gin.H{
			"name":            r.name,
			"avg_triage_min":  math.Round(r.avgTriageMin*10) / 10,
			"volume":          r.volume,
			"escalation_rate": math.Round(r.escalationRate*10) / 10,
		})
	}

	// ── Build incidents output ───────────────────────────────────────────────
	incOut := make([]gin.H, 0, len(openIncidents))
	for _, r := range openIncidents {
		incOut = append(incOut, gin.H{
			"id":          r.id,
			"title":       r.title,
			"severity":    r.severity,
			"age_hours":   r.ageHours,
			"assigned_to": r.assignedTo,
		})
	}

	if ageBuckets == nil {
		ageBuckets = []gin.H{}
	}

	c.JSON(http.StatusOK, gin.H{
		"analysts": analysts,
		"funnel": gin.H{
			"total":     funnelTotal,
			"triaged":   funnelTriaged,
			"escalated": funnelEscalated,
			"incidents": funnelIncidents,
			"resolved":  funnelResolved,
		},
		"age_buckets":        ageBuckets,
		"sla_compliance":     slaCompliance,
		"categories":         catsOut,
		"mttr":               mttrOut,
		"open_incidents":     incOut,
		"resolution_methods": buildResolutionMethods(resAutoCount, resAnalystCount, resFpCount, resEscCount),
	})
}

func buildResolutionMethods(auto, analyst, fp, escalated int) []gin.H {
	total := auto + analyst + fp + escalated
	pct := func(v int) float64 {
		if total == 0 {
			return 0
		}
		return math.Round(float64(v)/float64(total)*1000) / 10
	}
	return []gin.H{
		{"label": "自動解決", "value": pct(auto), "color": "#10b981"},
		{"label": "アナリスト対応", "value": pct(analyst), "color": "#3b82f6"},
		{"label": "エスカレーション", "value": pct(escalated), "color": "#f59e0b"},
		{"label": "誤検知", "value": pct(fp), "color": "#6b7280"},
	}
}
