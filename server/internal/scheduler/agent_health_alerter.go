package scheduler

// AgentHealthAlerter monitors agent health metrics and generates alerts
// when agents exceed configured thresholds.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

const (
	healthCheckInterval = 5 * time.Minute

	// cpuThreshold is the percentage above which a CPU alert is raised.
	cpuThreshold = 90.0
	// memThreshold is the percentage above which a memory alert is raised.
	memThreshold = 85.0
	// staleThreshold is how long an agent can be silent while still marked online
	// before being considered stale.
	staleThreshold = 10 * time.Minute
	// dedupWindow is the look-back window used to suppress duplicate alerts.
	dedupWindow = 1 * time.Hour
)

// AgentHealthAlerter monitors online agents and creates alerts for health issues.
type AgentHealthAlerter struct {
	pool *pgxpool.Pool
	nc   *nats.Conn
}

// NewAgentHealthAlerter creates an AgentHealthAlerter.
func NewAgentHealthAlerter(pool *pgxpool.Pool, nc *nats.Conn) *AgentHealthAlerter {
	return &AgentHealthAlerter{pool: pool, nc: nc}
}

// Run starts the 5-minute health-check ticker. Designed to be called as a goroutine.
func (a *AgentHealthAlerter) Run(ctx context.Context) {
	ticker := time.NewTicker(healthCheckInterval)
	defer ticker.Stop()
	slog.Info("エージェントヘルスアラーター起動")
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.checkHealth(ctx)
		}
	}
}

// healthIssue holds a detected health problem for one agent.
type healthIssue struct {
	agentID     string
	hostname    string
	description string
}

// checkHealth queries for agent health problems and creates alerts where needed.
func (a *AgentHealthAlerter) checkHealth(ctx context.Context) {
	var issues []healthIssue

	// ── 1. High CPU / memory from settings JSONB ─────────────────────────
	// The agents table may carry a settings JSONB column that agents populate
	// with runtime metrics. We query it only when the column is present; the
	// query is wrapped in a DO block so it fails silently on missing column.
	cpuMemIssues := a.checkCPUMemory(ctx)
	issues = append(issues, cpuMemIssues...)

	// ── 2. Stale agents (online but last_seen older than staleThreshold) ──
	staleIssues := a.checkStaleAgents(ctx)
	issues = append(issues, staleIssues...)

	// ── 3. Create alerts (with dedup) ─────────────────────────────────────
	for _, issue := range issues {
		a.maybeCreateAlert(ctx, issue)
	}
}

// checkCPUMemory queries online agents whose last heartbeat reported high CPU
// or memory usage. cpu_usage is a percentage; memory arrives as absolute MB and
// is converted to a percentage of total_memory_mb. Agents that have not yet
// reported metrics (metrics_updated_at IS NULL) are excluded.
func (a *AgentHealthAlerter) checkCPUMemory(ctx context.Context) []healthIssue {
	rows, err := a.pool.Query(ctx,
		`SELECT id::text, hostname,
		        COALESCE(cpu_usage, 0) AS cpu,
		        CASE WHEN COALESCE(total_memory_mb, 0) > 0
		             THEN COALESCE(memory_usage_mb, 0) / total_memory_mb * 100
		             ELSE 0 END AS mem
		 FROM agents
		 WHERE status = 'online'
		   AND metrics_updated_at IS NOT NULL
		   AND (
		       COALESCE(cpu_usage, 0) > $1
		    OR (COALESCE(total_memory_mb, 0) > 0
		        AND COALESCE(memory_usage_mb, 0) / total_memory_mb * 100 > $2)
		   )
		 LIMIT 50`,
		cpuThreshold, memThreshold,
	)
	if err != nil {
		// The column likely doesn't exist yet — degrade gracefully.
		slog.Debug("CPU/メモリヘルスチェックをスキップ", "error", err)
		return nil
	}
	defer rows.Close()

	var issues []healthIssue
	for rows.Next() {
		var id, hostname string
		var cpu, mem float64
		if scanErr := rows.Scan(&id, &hostname, &cpu, &mem); scanErr != nil {
			continue
		}
		var desc string
		if cpu > cpuThreshold && mem > memThreshold {
			desc = fmt.Sprintf("CPU使用率 %.1f%% (閾値: %.0f%%)、メモリ使用率 %.1f%% (閾値: %.0f%%) が高い状態です。",
				cpu, cpuThreshold, mem, memThreshold)
		} else if cpu > cpuThreshold {
			desc = fmt.Sprintf("CPU使用率 %.1f%% が閾値 %.0f%% を超えています。", cpu, cpuThreshold)
		} else {
			desc = fmt.Sprintf("メモリ使用率 %.1f%% が閾値 %.0f%% を超えています。", mem, memThreshold)
		}
		issues = append(issues, healthIssue{agentID: id, hostname: hostname, description: desc})
	}
	return issues
}

// checkStaleAgents returns agents that are still marked online but have not
// checked in within staleThreshold.
func (a *AgentHealthAlerter) checkStaleAgents(ctx context.Context) []healthIssue {
	rows, err := a.pool.Query(ctx,
		`SELECT id::text, hostname,
		        EXTRACT(EPOCH FROM (NOW() - last_seen))::int AS seconds_silent
		 FROM agents
		 WHERE status = 'online'
		   AND last_seen IS NOT NULL
		   AND last_seen < NOW() - $1::INTERVAL
		 LIMIT 50`,
		fmt.Sprintf("%.0f seconds", staleThreshold.Seconds()),
	)
	if err != nil {
		slog.Debug("ステールエージェントチェック失敗", "error", err)
		return nil
	}
	defer rows.Close()

	var issues []healthIssue
	for rows.Next() {
		var id, hostname string
		var secondsSilent int
		if scanErr := rows.Scan(&id, &hostname, &secondsSilent); scanErr != nil {
			continue
		}
		silent := time.Duration(secondsSilent) * time.Second
		desc := fmt.Sprintf(
			"エージェントは 'online' として登録されていますが、%s 以上ハートビートを送信していません（最終確認: %s 前）。",
			staleThreshold, silent.Round(time.Second),
		)
		issues = append(issues, healthIssue{agentID: id, hostname: hostname, description: desc})
	}
	return issues
}

// maybeCreateAlert checks dedup and creates an alert if no similar alert
// was raised for this agent in the last dedupWindow.
func (a *AgentHealthAlerter) maybeCreateAlert(ctx context.Context, issue healthIssue) {
	// Dedup: skip if a health-monitor alert already exists for this agent in the last hour.
	var existing int
	_ = a.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM alerts
		 WHERE agent_id = $1::uuid
		   AND title LIKE 'エージェント%ヘルス警告'
		   AND created_at > NOW() - $2::INTERVAL`,
		issue.agentID,
		fmt.Sprintf("%.0f seconds", dedupWindow.Seconds()),
	).Scan(&existing)

	if existing > 0 {
		slog.Debug("ヘルスアラートは重複のためスキップします", "agent_id", issue.agentID)
		return
	}

	title := fmt.Sprintf("エージェント %s ヘルス警告", issue.hostname)

	var alertID string
	err := a.pool.QueryRow(ctx,
		`INSERT INTO alerts (agent_id, title, description, severity, status)
		 VALUES ($1::uuid, $2, $3, 5, 'open')
		 RETURNING id::text`,
		issue.agentID, title, issue.description,
	).Scan(&alertID)
	if err != nil {
		slog.Error("ヘルスアラートの作成に失敗しました", "agent_id", issue.agentID, "error", err)
		return
	}

	slog.Info("エージェントヘルスアラートを作成しました",
		"alert_id", alertID,
		"agent_id", issue.agentID,
		"hostname", issue.hostname,
	)

	// Publish NATS notification so consumers can react immediately.
	if a.nc != nil {
		payload, _ := json.Marshal(map[string]string{
			"alert_id":    alertID,
			"agent_id":    issue.agentID,
			"hostname":    issue.hostname,
			"description": issue.description,
		})
		if pubErr := a.nc.Publish("alerts.new", payload); pubErr != nil {
			slog.Warn("alerts.new NATSパブリッシュに失敗しました", "error", pubErr)
		}
	}
}
