package detectionmetrics

// Tracks detection performance metrics: MTTD, MTTR, false positive rates

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// RuleStat holds false positive statistics for a single detection rule.
type RuleStat struct {
	RuleName   string  `json:"rule_name"`
	FPCount    int     `json:"fp_count"`
	TotalCount int     `json:"total_count"`
	FPRate     float64 `json:"fp_rate"`
}

// TrendPoint represents a daily alert count data point.
type TrendPoint struct {
	Date  string `json:"date"`
	Count int    `json:"count"`
}

// DetectionMetrics holds computed performance metrics for a given period.
type DetectionMetrics struct {
	Period                string                 `json:"period"` // 24h/7d/30d
	TotalAlerts           int                    `json:"total_alerts"`
	TruePositives         int                    `json:"true_positives"`
	FalsePositives        int                    `json:"false_positives"`
	FalsePositiveRate     float64                `json:"false_positive_rate"` // 0-1
	MTTD                  float64                `json:"mttd_minutes"`        // mean time to detect
	MTTR                  float64                `json:"mttr_hours"`          // mean time to respond
	DetectionCoverage     float64                `json:"detection_coverage"`  // % of MITRE techniques covered
	TopFalsePositiveRules []RuleStat             `json:"top_fp_rules"`
	TuningRecommendations []TuningRecommendation `json:"tuning_recommendations"` // data-driven FP-reduction suggestions
	MITRECoverage         map[string]int         `json:"mitre_coverage"`         // tactic -> rule count
	SeverityDistribution  map[string]int         `json:"severity_distribution"`
	TrendData             []TrendPoint           `json:"trend_data"` // daily alert counts for period
}

// Tracker computes detection performance metrics from the alerts table.
type Tracker struct {
	pool *pgxpool.Pool
}

// NewTracker creates a new Tracker.
func NewTracker(pool *pgxpool.Pool) *Tracker {
	return &Tracker{pool: pool}
}

// periodToInterval converts a period string (24h, 7d, 30d) to a PostgreSQL interval.
func periodToInterval(period string) string {
	switch period {
	case "24h":
		return "24 hours"
	case "7d":
		return "7 days"
	case "30d":
		return "30 days"
	default:
		return "7 days"
	}
}

// Calculate computes full detection metrics for the given period.
func (t *Tracker) Calculate(ctx context.Context, period string) (*DetectionMetrics, error) {
	interval := periodToInterval(period)

	m := &DetectionMetrics{
		Period:                period,
		MITRECoverage:         map[string]int{},
		SeverityDistribution:  map[string]int{},
		TopFalsePositiveRules: []RuleStat{},
		TuningRecommendations: []TuningRecommendation{},
		TrendData:             []TrendPoint{},
	}

	if t.pool == nil {
		return m, nil
	}

	// ── Total alert counts ───────────────────────────────────────────────────
	err := t.pool.QueryRow(ctx, `
		SELECT
			COUNT(*),
			COUNT(*) FILTER (WHERE status = 'false_positive'),
			COUNT(*) FILTER (WHERE status NOT IN ('false_positive','open') AND status IS NOT NULL)
		FROM alerts
		WHERE created_at > NOW() - $1::interval`,
		interval,
	).Scan(&m.TotalAlerts, &m.FalsePositives, &m.TruePositives)
	if err != nil {
		slog.Warn("detectionmetrics: alert count query failed", "error", err)
	}

	if m.TotalAlerts > 0 {
		m.FalsePositiveRate = float64(m.FalsePositives) / float64(m.TotalAlerts)
	}

	// ── MTTD: avg(alert.created_at - event.created_at) ──────────────────────
	// Attempt to join alerts to their triggering event via event_id if column exists.
	var mttdMinutes *float64
	mttdErr := t.pool.QueryRow(ctx, `
		SELECT EXTRACT(EPOCH FROM AVG(a.created_at - e.created_at)) / 60.0
		FROM alerts a
		JOIN events e ON e.id::text = a.event_id::text
		WHERE a.created_at > NOW() - $1::interval
		  AND e.created_at IS NOT NULL`,
		interval,
	).Scan(&mttdMinutes)
	if mttdErr == nil && mttdMinutes != nil {
		m.MTTD = *mttdMinutes
	}

	// ── MTTR: avg(updated_at - created_at) for resolved/closed alerts ────────
	var mttrHours *float64
	_ = t.pool.QueryRow(ctx, `
		SELECT EXTRACT(EPOCH FROM AVG(updated_at - created_at)) / 3600.0
		FROM alerts
		WHERE created_at > NOW() - $1::interval
		  AND status IN ('resolved','closed')
		  AND updated_at > created_at`,
		interval,
	).Scan(&mttrHours)
	if mttrHours != nil {
		m.MTTR = *mttrHours
	}

	// ── Severity distribution ────────────────────────────────────────────────
	sevRows, err := t.pool.Query(ctx, `
		SELECT COALESCE(severity::text, 'unknown'), COUNT(*)
		FROM alerts
		WHERE created_at > NOW() - $1::interval
		GROUP BY severity`,
		interval,
	)
	if err == nil {
		defer sevRows.Close()
		for sevRows.Next() {
			var sev string
			var cnt int
			if err := sevRows.Scan(&sev, &cnt); err == nil {
				m.SeverityDistribution[sev] = cnt
			}
		}
	}

	// ── Top false positive rules ─────────────────────────────────────────────
	//
	// Grouped by alerts.title, NOT by a rule_name column: no such column has ever
	// existed on alerts (see migration 001 and the current schema), so the previous
	// query failed with SQLSTATE 42703 on every call. The error landed in `err`,
	// the `if err == nil` below skipped the whole block, and TopFalsePositiveRules
	// was returned as an empty list — silently, with no log line. The feature has
	// never returned a row. Same silent-failure class as the ingestion reachability
	// bugs (#480/#491/#492): the code is present, the caller looks healthy, and the
	// output is quietly empty.
	//
	// title is the right grouping key rather than rule_id because the built-in
	// Sigma path and the stateful runtime detectors (discovery / file_burst /
	// lateral_fanout / exfil_volume) both persist alerts with rule_id NULL —
	// grouping on rule_id would collapse every one of them into a single anonymous
	// bucket. This matches how cmd/fpsoak-report attributes false positives, so
	// the dashboard and the soak scorecard name the same offenders.
	fpRows, err := t.pool.Query(ctx, `
		SELECT
			COALESCE(NULLIF(title, ''), 'unknown'),
			COUNT(*) FILTER (WHERE status = 'false_positive') AS fp_count,
			COUNT(*) AS total_count
		FROM alerts
		WHERE created_at > NOW() - $1::interval
		GROUP BY 1
		HAVING COUNT(*) FILTER (WHERE status = 'false_positive') > 0
		ORDER BY fp_count DESC
		LIMIT 10`,
		interval,
	)
	if err != nil {
		slog.Warn("誤検知の多いルールの集計に失敗しました", "error", err)
	}
	if err == nil {
		defer fpRows.Close()
		for fpRows.Next() {
			var rs RuleStat
			if err := fpRows.Scan(&rs.RuleName, &rs.FPCount, &rs.TotalCount); err == nil {
				if rs.TotalCount > 0 {
					rs.FPRate = float64(rs.FPCount) / float64(rs.TotalCount)
				}
				m.TopFalsePositiveRules = append(m.TopFalsePositiveRules, rs)
			}
		}
	}
	if m.TopFalsePositiveRules == nil {
		m.TopFalsePositiveRules = []RuleStat{}
	}

	// Data-driven FP-reduction recommendations from the per-rule stats just computed.
	// Advisory only — surfaced for operator review, never auto-applied.
	m.TuningRecommendations = RecommendTuning(m.TopFalsePositiveRules)
	if m.TuningRecommendations == nil {
		m.TuningRecommendations = []TuningRecommendation{}
	}

	// ── MITRE coverage (tactic → rule count) ─────────────────────────────────
	mitreRows, err := t.pool.Query(ctx, `
		SELECT COALESCE(r.mitre_tactic, 'unknown'), COUNT(DISTINCT r.id)
		FROM rules r
		WHERE r.enabled = true
		GROUP BY r.mitre_tactic`)
	if err == nil {
		defer mitreRows.Close()
		totalTactics := 0
		coveredTactics := 0
		for mitreRows.Next() {
			var tactic string
			var count int
			if err := mitreRows.Scan(&tactic, &count); err == nil {
				m.MITRECoverage[tactic] = count
				totalTactics++
				if count > 0 {
					coveredTactics++
				}
			}
		}
		// Coverage = fraction of known MITRE ATT&CK tactics with at least one rule.
		// There are 14 top-level MITRE ATT&CK tactics; use max(known,14) as denominator.
		denom := 14
		if totalTactics > denom {
			denom = totalTactics
		}
		if denom > 0 {
			m.DetectionCoverage = float64(coveredTactics) / float64(denom)
		}
	}

	// ── Daily trend data ─────────────────────────────────────────────────────
	m.TrendData = t.buildTrendData(ctx, interval)

	return m, nil
}

// buildTrendData constructs a daily alert count slice for the given interval.
func (t *Tracker) buildTrendData(ctx context.Context, interval string) []TrendPoint {
	rows, err := t.pool.Query(ctx, `
		SELECT to_char(DATE_TRUNC('day', created_at), 'YYYY-MM-DD'), COUNT(*)
		FROM alerts
		WHERE created_at > NOW() - $1::interval
		GROUP BY DATE_TRUNC('day', created_at)
		ORDER BY DATE_TRUNC('day', created_at)`,
		interval,
	)
	if err != nil {
		return []TrendPoint{}
	}
	defer rows.Close()

	var trend []TrendPoint
	for rows.Next() {
		var tp TrendPoint
		if err := rows.Scan(&tp.Date, &tp.Count); err == nil {
			trend = append(trend, tp)
		}
	}
	if trend == nil {
		return []TrendPoint{}
	}
	return trend
}

// GetMITRECoverage returns a map of MITRE tactic → list of covered technique IDs.
func (t *Tracker) GetMITRECoverage(ctx context.Context) (map[string][]string, error) {
	coverage := map[string][]string{}
	if t.pool == nil {
		return coverage, nil
	}

	rows, err := t.pool.Query(ctx, `
		SELECT COALESCE(mitre_tactic, 'unknown'), COALESCE(mitre_technique, '')
		FROM rules
		WHERE enabled = true
		  AND mitre_technique IS NOT NULL
		  AND mitre_technique <> ''
		ORDER BY mitre_tactic, mitre_technique`)
	if err != nil {
		slog.Warn("detectionmetrics: GetMITRECoverage query failed", "error", err)
		return coverage, nil
	}
	defer rows.Close()

	for rows.Next() {
		var tactic, technique string
		if err := rows.Scan(&tactic, &technique); err == nil {
			coverage[tactic] = append(coverage[tactic], technique)
		}
	}

	// Deduplicate techniques per tactic.
	for tactic, techs := range coverage {
		seen := map[string]bool{}
		uniq := []string{}
		for _, tech := range techs {
			if !seen[tech] {
				seen[tech] = true
				uniq = append(uniq, tech)
			}
		}
		coverage[tactic] = uniq
	}

	return coverage, nil
}

// GetTrend returns daily alert trend data for the given period.
func (t *Tracker) GetTrend(ctx context.Context, period string) []TrendPoint {
	if t.pool == nil {
		return []TrendPoint{}
	}
	_ = time.Now() // ensure time import is used
	return t.buildTrendData(ctx, periodToInterval(period))
}
