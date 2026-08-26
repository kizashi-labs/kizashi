package detection

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/edr-platform/server/internal/tick"
)

// maxLinkedAlertsPerRun bounds how many constituent alerts a single correlation
// run links into one incident, so a pathologically noisy agent can't produce an
// unbounded batch of INSERTs. LinkAlerts is idempotent, so alerts beyond the cap
// in one run are simply linked on a later run if still in-window.
const maxLinkedAlertsPerRun = 500

// IncidentCreator is the minimal interface CorrelationEngine needs to
// materialise correlated agent activity as incidents and link the constituent
// alerts for analyst drill-down.
type IncidentCreator interface {
	// CreateCorrelationIncident creates an incident summarising an agent's
	// correlated activity (the set of MITRE techniques it triggered within the
	// window) and returns the new incident ID.
	CreateCorrelationIncident(ctx context.Context, agentID string, techniques []string, alertCount int) (string, error)
	// LinkAlerts attaches the given alert IDs to an incident. Idempotent.
	LinkAlerts(ctx context.Context, incidentID string, alertIDs []string) error
}

// CorrelationEngine periodically scans alerts and bundles each agent's correlated
// activity within the window into a single incident "case". Unlike a per-technique
// grouping, one incident covers all the techniques an agent triggered in the
// window, so a multi-stage attack (execution → injection → credential access →
// lateral movement) surfaces as ONE correlated case rather than N fragments. The
// constituent alerts are linked into the incident for drill-down, and an active
// case absorbs new alerts instead of spawning a fresh incident every window.
type CorrelationEngine struct {
	pool          *pgxpool.Pool
	incidentStore IncidentCreator
	threshold     int
	window        time.Duration
}

// NewCorrelationEngine returns a new CorrelationEngine with default settings
// (threshold=3, window=1 hour).
func NewCorrelationEngine(pool *pgxpool.Pool, ic IncidentCreator) *CorrelationEngine {
	return &CorrelationEngine{
		pool:          pool,
		incidentStore: ic,
		threshold:     3,
		window:        1 * time.Hour,
	}
}

// NewCorrelationEngineWithConfig creates a CorrelationEngine with explicit threshold and window.
// threshold: minimum alert count to create an incident (must be >= 1).
// window: time window to look back (must be > 0).
func NewCorrelationEngineWithConfig(pool *pgxpool.Pool, ic IncidentCreator, threshold int, window time.Duration) *CorrelationEngine {
	if threshold < 1 {
		threshold = 3
	}
	if window <= 0 {
		window = time.Hour
	}
	return &CorrelationEngine{
		pool:          pool,
		incidentStore: ic,
		threshold:     threshold,
		window:        window,
	}
}

// Run executes the correlation check every 5 minutes until ctx is cancelled.
func (ce *CorrelationEngine) Run(ctx context.Context) {
	// Run once on startup
	tick.Run(ctx, "correlation_engine", ce.runOnce)

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			tick.Run(ctx, "correlation_engine", ce.runOnce)
		}
	}
}

// agentActivity holds one agent's correlated activity within the window: the
// distinct MITRE techniques it triggered, the constituent alert IDs and the total
// alert count.
type agentActivity struct {
	agentID    string
	techniques []string
	alertIDs   []string
	count      int
}

func (ce *CorrelationEngine) runOnce(ctx context.Context) {
	// Per agent, collect the distinct MITRE techniques and the alert IDs seen in
	// the window. An agent qualifies for a correlation case when it has at least
	// `threshold` technique-bearing alerts — this fires both on a single repeated
	// technique AND on a multi-technique kill chain (which per-technique grouping
	// would have split into separate incidents).
	// The `~ '^T[0-9]'` filter keeps real ATT&CK technique IDs (T1059, T1059.001)
	// and drops non-technique tags that leak into mitre_technique (tactic IDs like
	// TA0000, framework tags like "attack.execution"), so a correlated case lists
	// only genuine techniques.
	rows, err := ce.pool.Query(ctx, `
		SELECT a.agent_id::text,
		       array_agg(DISTINCT a.mitre_technique) AS techniques,
		       array_agg(a.id::text ORDER BY a.created_at DESC) AS alert_ids,
		       COUNT(*) AS cnt
		FROM alerts a
		WHERE a.created_at > NOW() - $1::interval
		  AND a.mitre_technique ~ '^T[0-9]'
		GROUP BY a.agent_id
		HAVING COUNT(*) >= $2
	`, ce.window.String(), ce.threshold)
	if err != nil {
		tick.FailComponent(ctx, "correlation", err, "CorrelationEngine: クエリエラー (無視します)")
		return
	}
	defer rows.Close()

	var activity []agentActivity
	for rows.Next() {
		var a agentActivity
		if err := rows.Scan(&a.agentID, &a.techniques, &a.alertIDs, &a.count); err != nil {
			tick.Fail(ctx, err, "CorrelationEngine: 行スキャンエラー")
			continue
		}
		a.techniques = sortedNonEmpty(a.techniques)
		// Bound the alert-link batch per run; LinkAlerts is idempotent so any
		// overflow links on a later run while still in-window.
		if len(a.alertIDs) > maxLinkedAlertsPerRun {
			a.alertIDs = a.alertIDs[:maxLinkedAlertsPerRun]
		}
		activity = append(activity, a)
	}
	if err := rows.Err(); err != nil {
		tick.Fail(ctx, err, "CorrelationEngine: 行イテレーションエラー")
	}

	for _, a := range activity {
		ce.upsertCase(ctx, a)
	}
}

// upsertCase attaches the agent's activity to its active correlation case,
// creating a new incident if none is active within the window. Either way the
// constituent alerts are linked for drill-down.
func (ce *CorrelationEngine) upsertCase(ctx context.Context, a agentActivity) {
	// Find this agent's active case: an agent-level correlation group (sentinel
	// technique '*') whose incident is still open/investigating and was last seen
	// within the window. Absorbing into it prevents the per-window incident churn
	// the old per-(agent,technique) INSERT produced.
	var caseID, incidentID string
	err := ce.pool.QueryRow(ctx, `
		SELECT cg.id::text, cg.incident_id::text
		FROM correlation_groups cg
		JOIN incidents i ON i.id = cg.incident_id
		WHERE cg.agent_id       = $1
		  AND cg.mitre_technique = '*'
		  AND cg.incident_id    IS NOT NULL
		  AND cg.last_seen_at    > NOW() - $2::interval
		  AND i.status IN ('open', 'investigating')
		ORDER BY cg.last_seen_at DESC
		LIMIT 1
	`, a.agentID, ce.window.String()).Scan(&caseID, &incidentID)

	switch {
	case err == nil:
		// Active case exists: refresh its last-seen + count so it stays alive and
		// absorbs the new alerts, instead of opening a duplicate incident.
		if _, e := ce.pool.Exec(ctx, `
			UPDATE correlation_groups
			SET last_seen_at = NOW(), alert_count = $2
			WHERE id = $1::uuid
		`, caseID, a.count); e != nil {
			slog.Warn("CorrelationEngine: ケース更新に失敗しました", "case_id", caseID, "error", e)
		}
	case errors.Is(err, pgx.ErrNoRows):
		// No active case: create a fresh correlation incident and record the
		// agent-level group so subsequent runs absorb into it.
		id, e := ce.incidentStore.CreateCorrelationIncident(ctx, a.agentID, a.techniques, a.count)
		if e != nil {
			// **ここは `tick.Run` で回している仕事の中です。** 部品の
			// 件数だけ数えると、この回は成功として刻まれます。
			tick.FailComponent(ctx, "correlation", e, "CorrelationEngine: インシデント自動作成に失敗しました",
				"agent_id", a.agentID, "techniques", a.techniques, "alert_count", a.count)
			return
		}
		incidentID = id
		if _, e := ce.pool.Exec(ctx, `
			INSERT INTO correlation_groups
			    (agent_id, mitre_technique, first_seen_at, last_seen_at, alert_count, incident_id)
			VALUES ($1, '*', NOW(), NOW(), $2, $3::uuid)
		`, a.agentID, a.count, incidentID); e != nil {
			slog.Warn("CorrelationEngine: correlation_groups への書き込みに失敗しました", "incident_id", incidentID, "error", e)
		}
		slog.Info("CorrelationEngine: 相関インシデントを自動作成しました",
			"agent_id", a.agentID, "techniques", a.techniques, "alert_count", a.count, "incident_id", incidentID)
	default:
		slog.Warn("CorrelationEngine: ケース検索に失敗しました", "agent_id", a.agentID, "error", err)
		return
	}

	// Link the constituent alerts (idempotent) so the incident drills down to its
	// evidence. Without this, an auto-created incident shows only a summary and an
	// analyst cannot pivot to the underlying alerts.
	if incidentID != "" && len(a.alertIDs) > 0 {
		if e := ce.incidentStore.LinkAlerts(ctx, incidentID, a.alertIDs); e != nil {
			slog.Warn("CorrelationEngine: アラート紐付けに失敗しました", "incident_id", incidentID, "error", e)
		}
	}
}

// sortedNonEmpty returns the input with blanks removed and a stable order, so
// incident titles list techniques deterministically.
func sortedNonEmpty(in []string) []string {
	out := in[:0:0]
	for _, s := range in {
		if strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// BuildCorrelationIncidentContent returns the title, description and severity for
// an auto-created correlation incident, given the agent display name, the sorted
// set of correlated MITRE techniques and the total alert count. Severity scales
// with the breadth of techniques: a multi-tactic kill chain is more severe than a
// single repeated technique. Pure (no I/O) so it is unit-tested directly.
func BuildCorrelationIncidentContent(displayName string, techniques []string, alertCount int) (title, description string, severity int) {
	techList := strings.Join(techniques, ", ")
	if techList == "" {
		techList = "不明"
	}
	// 1 technique → sev 7 (matches the previous fixed default); each additional
	// distinct technique adds 1, capped at 10.
	severity = 6 + len(techniques)
	if severity > 10 {
		severity = 10
	}
	if severity < 7 {
		severity = 7
	}
	if len(techniques) >= 2 {
		title = fmt.Sprintf("[相関] 多段攻撃の疑い: エージェント %s で %d 戦術横断 (%s)",
			displayName, len(techniques), techList)
		description = fmt.Sprintf(
			"エージェント %s が相関ウィンドウ内に %d 個の MITRE テクニック (%s) にわたり計 %d 件のアラートをトリガーしました。"+
				"複数戦術の相関により多段攻撃の疑いとしてインシデントを自動生成しました。構成アラートを本インシデントに紐付けています。",
			displayName, len(techniques), techList, alertCount)
	} else {
		title = fmt.Sprintf("[相関] エージェント %s で %s の反復アラート (%d件)",
			displayName, techList, alertCount)
		description = fmt.Sprintf(
			"エージェント %s が相関ウィンドウ内に MITRE テクニック %s のアラートを計 %d 件トリガーしました。"+
				"相関エンジンによりインシデントを自動生成し、構成アラートを紐付けています。",
			displayName, techList, alertCount)
	}
	return title, description, severity
}
