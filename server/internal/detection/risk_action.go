package detection

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
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
}

// NewRiskActionMonitor creates a new RiskActionMonitor.
func NewRiskActionMonitor(pool *pgxpool.Pool, commander RiskCommander) *RiskActionMonitor {
	return &RiskActionMonitor{pool: pool, commander: commander}
}

// Run checks every 2 minutes for agents that exceed configured risk thresholds.
// It blocks until ctx is cancelled.
func (m *RiskActionMonitor) Run(ctx context.Context) {
	// Run once immediately at startup
	m.runOnce(ctx)

	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.runOnce(ctx)
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
		slog.Warn("RiskActionMonitor: クエリエラー", "error", err)
		return
	}
	defer rows.Close()

	var matches []riskMatch
	for rows.Next() {
		var m riskMatch
		if err := rows.Scan(&m.agentID, &m.riskScore); err != nil {
			slog.Warn("RiskActionMonitor: 行スキャンエラー", "error", err)
			continue
		}
		matches = append(matches, m)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("RiskActionMonitor: 行イテレーションエラー", "error", err)
	}

	for _, match := range matches {
		reason := fmt.Sprintf("リスクスコア自動隔離: スコア %d がしきい値を超えました", match.riskScore)
		if err := m.commander.IsolateAgent(ctx, match.agentID, reason); err != nil {
			slog.Error("RiskActionMonitor: 自動隔離に失敗しました",
				"agent_id", match.agentID,
				"risk_score", match.riskScore,
				"error", err,
			)
			continue
		}

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
		if err := m.saveAlert(ctx, alert); err != nil {
			slog.Warn("RiskActionMonitor: アラートの保存に失敗しました",
				"agent_id", match.agentID,
				"error", err,
			)
		}

		slog.Info("RiskActionMonitor: エージェントを自動隔離しました",
			"agent_id", match.agentID,
			"risk_score", match.riskScore,
		)
	}
}

// saveAlert inserts a minimal alert row directly via the pool.
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
