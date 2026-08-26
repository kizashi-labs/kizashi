package detection

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/edr-platform/server/internal/tick"
)

// RiskCommander is implemented by any component that can isolate an agent.
type RiskCommander interface {
	IsolateAgent(ctx context.Context, agentID, reason string) error
}

// RiskActionMonitor periodically checks whether any active agents have exceeded
// a configured risk-score threshold and isolates them automatically.
type RiskActionMonitor struct {
	pool      *pgxpool.Pool
	commander RiskCommander

	// failed は隔離に失敗したエージェント。2分ごとに再試行するので、
	// 失敗するたびにアラートを立てると同じ内容が延々と積まれます。
	// 最初の失敗で1件立て、成功するか対象から外れるまで黙ります。
	mu     sync.Mutex
	failed map[string]bool

	// saveAlertFn はアラート保存の差し替え口。既定は saveAlert です。
	// 「隔離に失敗したときアラートを立てる」かどうかは、データベース抜きで
	// 確かめられなければ、立てるのをやめても誰も気づけません。
	saveAlertFn func(*StoredAlert) error
}

// NewRiskActionMonitor creates a new RiskActionMonitor.
func NewRiskActionMonitor(pool *pgxpool.Pool, commander RiskCommander) *RiskActionMonitor {
	return &RiskActionMonitor{pool: pool, commander: commander, failed: map[string]bool{}}
}

// Run checks every 2 minutes for agents that exceed configured risk thresholds.
// It blocks until ctx is cancelled.
func (m *RiskActionMonitor) Run(ctx context.Context) {
	// Run once immediately at startup
	tick.Run(ctx, "risk_action_monitor", m.runOnce)

	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			tick.Run(ctx, "risk_action_monitor", m.runOnce)
		}
	}
}

type riskMatch struct {
	agentID   string
	riskScore int
}

func (m *RiskActionMonitor) runOnce(ctx context.Context) {
	// Find enabled isolate rules and agents whose computed risk_score meets the threshold.
	// We derive the risk score inline (matching the same formula used by the /risk-score endpoint)
	// rather than storing a stale cached column.
	rows, err := m.pool.Query(ctx, `
		SELECT DISTINCT ON (a.id)
		    a.id::text,
		    LEAST(
		        COALESCE(COUNT(al.id) FILTER (WHERE al.severity >= 9 AND al.status IN ('open','investigating')), 0) * 25 +
		        COALESCE(COUNT(al.id) FILTER (WHERE al.severity >= 7 AND al.severity < 9 AND al.status IN ('open','investigating')), 0) * 15 +
		        COALESCE(COUNT(al.id) FILTER (WHERE al.severity >= 4 AND al.severity < 7 AND al.status IN ('open','investigating')), 0) * 5 +
		        COALESCE(COUNT(v.id)  FILTER (WHERE v.severity = 'critical' AND v.status = 'open'), 0) * 20 +
		        COALESCE(COUNT(v.id)  FILTER (WHERE v.severity = 'high'     AND v.status = 'open'), 0) * 10,
		        100
		    )::int AS risk_score
		FROM agents a
		CROSS JOIN risk_action_rules r
		LEFT JOIN alerts al ON al.agent_id = a.id
		LEFT JOIN vulnerabilities v ON v.agent_id = a.id
		WHERE r.enabled = true
		  AND r.action = 'isolate'
		  AND a.status != 'isolated'
		  AND a.status = 'online'
		GROUP BY a.id, r.threshold
		HAVING LEAST(
		    COALESCE(COUNT(al.id) FILTER (WHERE al.severity >= 9 AND al.status IN ('open','investigating')), 0) * 25 +
		    COALESCE(COUNT(al.id) FILTER (WHERE al.severity >= 7 AND al.severity < 9 AND al.status IN ('open','investigating')), 0) * 15 +
		    COALESCE(COUNT(al.id) FILTER (WHERE al.severity >= 4 AND al.severity < 7 AND al.status IN ('open','investigating')), 0) * 5 +
		    COALESCE(COUNT(v.id)  FILTER (WHERE v.severity = 'critical' AND v.status = 'open'), 0) * 20 +
		    COALESCE(COUNT(v.id)  FILTER (WHERE v.severity = 'high'     AND v.status = 'open'), 0) * 10,
		    100
		)::int >= r.threshold
	`)
	if err != nil {
		tick.FailComponent(ctx, "risk_action", err, "RiskActionMonitor: クエリエラー")
		return
	}
	defer rows.Close()

	var matches []riskMatch
	for rows.Next() {
		var m riskMatch
		if err := rows.Scan(&m.agentID, &m.riskScore); err != nil {
			tick.Fail(ctx, err, "RiskActionMonitor: 行スキャンエラー")
			continue
		}
		matches = append(matches, m)
	}
	if err := rows.Err(); err != nil {
		tick.Fail(ctx, err, "RiskActionMonitor: 行イテレーションエラー")
	}

	m.applyIsolations(ctx, matches)
}

// applyIsolations isolates each match and records what happened either way.
//
// Split out of runOnce because runOnce needs a database to reach it. With the
// loop inline, deleting the failure alert or the success reset changed no test
// — which is the same "the check is there but nothing can see it" the rest of
// this package has been about.
func (m *RiskActionMonitor) applyIsolations(ctx context.Context, matches []riskMatch) {
	for _, match := range matches {
		reason := fmt.Sprintf("リスクスコア自動隔離: スコア %d がしきい値を超えました", match.riskScore)
		if err := m.commander.IsolateAgent(ctx, match.agentID, reason); err != nil {
			// 成功したときだけ severity 10 のアラートを立て、失敗は
			// ログだけでした。つまり SOC から見える記録は、封じ込めが
			// 効いたときにしか存在しません。高リスクの端末を隔離しようと
			// して隔離できなかったことは、画面上のどこにも出ませんでした。
			tick.Fail(ctx, err, "RiskActionMonitor: 自動隔離に失敗しました",
				"agent_id", match.agentID,
				"risk_score", match.riskScore,
			)
			if m.markFailed(match.agentID) {
				m.saveFailureAlert(ctx, match, err)
			}
			continue
		}
		m.clearFailed(match.agentID)

		// Record an alert explaining the auto-isolation
		alert := &StoredAlert{
			ID:      generateAlertID(),
			AgentID: match.agentID,
			// RuleID は空: alerts.rule_id は uuid 型。非UUID文字列は 22P02 で
			// INSERT 失敗し自動隔離アラートが保存されない。識別は RuleName が担う。
			RuleName:    "リスクスコア自動隔離",
			Severity:    10,
			Status:      "open",
			Title:       fmt.Sprintf("リスクスコアしきい値超過による自動隔離 (スコア: %d)", match.riskScore),
			Description: reason,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}
		if err := m.storeAlert(ctx, alert); err != nil {
			tick.Fail(ctx, err, "RiskActionMonitor: アラートの保存に失敗しました",
				"agent_id", match.agentID,
			)
		}

		slog.Info("RiskActionMonitor: エージェントを自動隔離しました",
			"risk_score", match.riskScore,
		)
	}
}

// saveAlert inserts a minimal alert row directly via the pool.
// markFailed records a failed isolation and reports whether this is the first
// one for that agent since it last succeeded. The monitor retries every two
// minutes, so alerting on each attempt would bury the first report under
// copies of itself.
func (m *RiskActionMonitor) markFailed(agentID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failed == nil {
		m.failed = map[string]bool{}
	}
	if m.failed[agentID] {
		return false
	}
	m.failed[agentID] = true
	return true
}

func (m *RiskActionMonitor) clearFailed(agentID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.failed, agentID)
}

// saveFailureAlert records that containment was attempted and did not happen.
//
// Same severity as the success alert on purpose: an endpoint over the
// threshold that is still on the network is not a lesser event than one that
// was taken off it.
func (m *RiskActionMonitor) saveFailureAlert(ctx context.Context, match riskMatch, cause error) {
	alert := &StoredAlert{
		ID:          generateAlertID(),
		AgentID:     match.agentID,
		RuleName:    "リスクスコア自動隔離の失敗",
		Severity:    10,
		Status:      "open",
		Title:       fmt.Sprintf("自動隔離に失敗しました (スコア: %d)", match.riskScore),
		Description: fmt.Sprintf("リスクスコア %d がしきい値を超えたため自動隔離を試みましたが失敗しました。この端末はまだネットワークに接続されています。原因: %v", match.riskScore, cause),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	if err := m.storeAlert(ctx, alert); err != nil {
		tick.Fail(ctx, err, "RiskActionMonitor: 自動隔離失敗のアラートを保存できませんでした",
			"agent_id", match.agentID)
	}
}

// storeAlert routes through saveAlertFn when a test has supplied one.
func (m *RiskActionMonitor) storeAlert(ctx context.Context, a *StoredAlert) error {
	if m.saveAlertFn != nil {
		return m.saveAlertFn(a)
	}
	return m.saveAlert(ctx, a)
}

func (m *RiskActionMonitor) saveAlert(ctx context.Context, a *StoredAlert) error {
	// alerts テーブルに rule_name 列は無い(表示名は rules への JOIN か title が担う)。
	// 以前は存在しない列を指定していて INSERT が常に 42703 で失敗し、自動隔離の
	// アラートが一度も保存されていなかった。rule_id は uuid 型なので空は NULL に。
	_, err := m.pool.Exec(ctx, `
		INSERT INTO alerts (id, agent_id, rule_id, severity, status, title, description, created_at, updated_at)
		VALUES ($1::uuid, $2::uuid, NULLIF($3, '')::uuid, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (id) DO NOTHING`,
		a.ID, a.AgentID, a.RuleID,
		a.Severity, a.Status, a.Title, a.Description,
		a.CreatedAt, a.UpdatedAt,
	)
	return err
}
