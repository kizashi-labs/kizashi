package detectionmetrics

// Tracks detection performance metrics: MTTD, MTTR, false positive rates

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/edr-platform/server/internal/detection"
)

// unknownTactic is the bucket for a technique detection.TacticForTechnique has
// no mapping for. It is not one of the 14 ATT&CK tactics.
//
// TacticForTechnique returns "" in that case, deliberately — its doc comment
// says callers must read the empty string as "tactic unknown" rather than as a
// tactic named "unknown". Naming the bucket here keeps that reading explicit
// and preserves what the old COALESCE(mitre_tactic, 'unknown') produced.
const unknownTactic = "unknown"

// tacticOf maps a technique ID to its tactic, folding the unmapped case into
// unknownTactic so an empty string never becomes a map key.
func tacticOf(technique string) string {
	if tactic := detection.TacticForTechnique(technique); tactic != "" {
		return tactic
	}
	return unknownTactic
}

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
	Period            string  `json:"period"` // 24h/7d/30d
	TotalAlerts       int     `json:"total_alerts"`
	TruePositives     int     `json:"true_positives"`
	FalsePositives    int     `json:"false_positives"`
	FalsePositiveRate float64 `json:"false_positive_rate"` // 0-1
	// MTTD is nil when it cannot be computed, rather than 0. A zero mean time to
	// detect on a SOC dashboard reads as instantaneous detection, which is the
	// opposite of "we have no data". See the MTTD block in Calculate.
	MTTD                  *float64               `json:"mttd_minutes"`       // mean time to detect
	MTTR                  float64                `json:"mttr_hours"`         // mean time to respond
	DetectionCoverage     float64                `json:"detection_coverage"` // % of MITRE techniques covered
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

	// ── MTTD: avg(alert.created_at - event.time) ────────────────────────────
	//
	// 以前は `JOIN events e ON e.id::text = a.event_id::text` と書いており、
	// events に id 列は無く (実列は event_id)、alerts にも event_id 列は無い
	// (実列は event_ids の配列)。events の時刻列も created_at ではなく time。
	// 3 つとも誤っていたため、このクエリは毎回失敗し MTTD は常に 0 だった。
	//
	// アラートは複数イベントを束ねうるので、最初のイベント (最古の time) を
	// 検知の起点とみなす。
	var mttdMinutes *float64
	mttdErr := t.pool.QueryRow(ctx, `
		SELECT EXTRACT(EPOCH FROM AVG(a.created_at - e.first_seen)) / 60.0
		FROM alerts a
		JOIN LATERAL (
			SELECT MIN("time") AS first_seen
			FROM events
			WHERE event_id = ANY(a.event_ids::uuid[])
		) e ON e.first_seen IS NOT NULL
		WHERE a.created_at > NOW() - $1::interval
		  AND a.event_ids IS NOT NULL
		  AND array_length(a.event_ids, 1) > 0`,
		interval,
	).Scan(&mttdMinutes)
	// 算出できなかったときは nil のまま置く。0 は「検知が即時だった」という
	// 測定値で、算出できなかったことと見分けが付かない (MTTD の型が *float64
	// なのはこのため)。クエリが失敗した場合も、該当するアラートが 1 件も
	// 無い場合も、埋めない。
	if mttdErr == nil && mttdMinutes != nil {
		m.MTTD = mttdMinutes
	}

	// ── MTTR: avg(updated_at - created_at) for resolved/closed alerts ────────
	var mttrHours *float64
	if err := t.pool.QueryRow(ctx, `
			SELECT EXTRACT(EPOCH FROM AVG(updated_at - created_at)) / 3600.0
			FROM alerts
			WHERE created_at > NOW() - $1::interval
			  AND status IN ('resolved','closed')
			  AND updated_at > created_at`,
		interval,
	).Scan(&mttrHours); err != nil {
		return nil, fmt.Errorf("数えられませんでした: %w", err)
	}
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
		if err := sevRows.Err(); err != nil {
			return nil, err
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
		if err := fpRows.Err(); err != nil {
			return nil, err
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
	//
	// rules に mitre_tactic 列は無い。実在するのは mitre_tags (テクニック ID の
	// 配列)。SQL ではテクニック単位に数え、タクティクへの写像は Go 側の
	// detection.TacticForTechnique に任せる (kill-chain 相関・コンプライアンス
	// スコアと同じ表)。
	// **タクティクごとに「ルール数」を数える。テクニックの出現数ではない。**
	// テクニック単位に数えて足し合わせると、同じタクティクに属するテクニックを
	// 複数持つ 1 本のルールがその数だけ計上され、網羅率が水増しされる
	// (T1003 と T1003.001 を両方書いた 1 本が credential-access を 2 と数える)。
	// 行はルール ID 付きで受け取り、タクティクごとに集合で持つ。
	mitreRows, err := t.pool.Query(ctx, `
		SELECT DISTINCT r.id::text, tag
		FROM rules r, unnest(COALESCE(r.mitre_tags, '{}')) AS tag
		WHERE r.enabled = true AND tag <> ''`)
	if err == nil {
		defer mitreRows.Close()
		perTactic := map[string]map[string]bool{}
		scanFailed := false
		for mitreRows.Next() {
			var ruleID, technique string
			if err := mitreRows.Scan(&ruleID, &technique); err != nil {
				// pgx は Scan の失敗で結果セットを閉じる。continue しても
				// 次の行は来ないので、部分的な網羅表を完成品として返さない。
				slog.Warn("detectionmetrics: MITRE 網羅表の行を読めませんでした", "error", err)
				scanFailed = true
				break
			}
			// 写像表に無いテクニックは捨てずに unknownTactic に寄せる。落とすと
			// 「対応表に無い」ことが集計から消え、ルールを書いた側からは戦術に
			// 数えられたのか取りこぼされたのか区別が付かない。
			tactic := tacticOf(technique)
			if perTactic[tactic] == nil {
				perTactic[tactic] = map[string]bool{}
			}
			perTactic[tactic][ruleID] = true
		}
		if err := mitreRows.Err(); err != nil || scanFailed {
			// 途中までの網羅表は「いま検知できる範囲」として読まれる。
			// 数え切れなかったなら、数字を出さない —— このファイルの
			// 他の走査 (severity / MTTR) と同じく error を返す。
			return nil, fmt.Errorf("MITRE 網羅表を数え切れませんでした: %w", err)
		}
		for tactic, ids := range perTactic {
			m.MITRECoverage[tactic] = len(ids)
		}
		// unknownTactic は 14 の ATT&CK 戦術のどれでもないので、分子にも
		// 分母にも入れない。入れると、対応表に無いテクニックを1つ持つルールが
		// カバレッジを 1/14 押し上げる。
		totalTactics := 0
		coveredTactics := 0
		for tactic, count := range m.MITRECoverage {
			if tactic == unknownTactic {
				continue
			}
			totalTactics++
			if count > 0 {
				coveredTactics++
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
	m.TrendData, err = t.buildTrendData(ctx, interval)
	if err != nil {
		return m, fmt.Errorf("検知件数の推移を読めませんでした: %w", err)
	}

	return m, nil
}

// buildTrendData constructs a daily alert count slice for the given interval.
//
// 読めなかったときは error を返します。以前は空のスライスを返していて、
// 線は「その期間の検知は0件」として描かれます。検知が止まっているのか、
// 数えられなかったのかは、見た目では区別がつきません。
func (t *Tracker) buildTrendData(ctx context.Context, interval string) ([]TrendPoint, error) {
	rows, err := t.pool.Query(ctx, `
		SELECT to_char(DATE_TRUNC('day', created_at), 'YYYY-MM-DD'), COUNT(*)
		FROM alerts
		WHERE created_at > NOW() - $1::interval
		GROUP BY DATE_TRUNC('day', created_at)
		ORDER BY DATE_TRUNC('day', created_at)`,
		interval,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var trend []TrendPoint
	for rows.Next() {
		var tp TrendPoint
		if err := rows.Scan(&tp.Date, &tp.Count); err == nil {
			trend = append(trend, tp)
		}
	}
	if err := rows.Err(); err != nil {
		// 途中で終わった集計は、読めなかった日を0件として描きます。
		return nil, err
	}
	if trend == nil {
		return []TrendPoint{}, nil
	}
	return trend, nil
}

// GetMITRECoverage returns a map of MITRE tactic → list of covered technique IDs.
func (t *Tracker) GetMITRECoverage(ctx context.Context) (map[string][]string, error) {
	coverage := map[string][]string{}
	if t.pool == nil {
		return coverage, nil
	}

	// mitre_tactic / mitre_technique 列は無い。mitre_tags を展開して
	// テクニックを取り、タクティクは Go 側で写す。
	rows, err := t.pool.Query(ctx, `
		SELECT DISTINCT tag
		FROM rules r, unnest(COALESCE(r.mitre_tags, '{}')) AS tag
		WHERE r.enabled = true AND tag <> ''
		ORDER BY tag`)
	if err != nil {
		slog.Warn("detectionmetrics: GetMITRECoverage query failed", "error", err)
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var technique string
		if err := rows.Scan(&technique); err != nil {
			continue
		}
		tactic := detection.TacticForTechnique(technique)
		if tactic == "" {
			tactic = "unknown"
		}
		coverage[tactic] = append(coverage[tactic], technique)
	}
	if err := rows.Err(); err != nil {
		// **途中までの網羅表を返しません。** 呼び出し側はこれを
		// 「いま検知できる範囲」として読みます。
		slog.Error("detectionmetrics: 網羅表の走査が途中で失敗しました", "error", err)
		return nil, err
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
func (t *Tracker) GetTrend(ctx context.Context, period string) ([]TrendPoint, error) {
	if t.pool == nil {
		return []TrendPoint{}, nil
	}
	return t.buildTrendData(ctx, periodToInterval(period))
}
