package scheduler

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// HeartbeatMonitor checks for agents that haven't sent a heartbeat recently
// and creates alerts for them.
type HeartbeatMonitor struct {
	pool             *pgxpool.Pool
	checkInterval    time.Duration
	offlineThreshold time.Duration
}

func NewHeartbeatMonitor(pool *pgxpool.Pool) *HeartbeatMonitor {
	return &HeartbeatMonitor{
		pool:             pool,
		checkInterval:    2 * time.Minute,
		offlineThreshold: 5 * time.Minute,
	}
}

// Run starts the heartbeat monitor loop.
func (m *HeartbeatMonitor) Run(ctx context.Context) {
	ticker := time.NewTicker(m.checkInterval)
	defer ticker.Stop()
	slog.Info("ハートビートモニター起動", "threshold", m.offlineThreshold)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			trackRun(ctx, "heartbeat_monitor", m.check)
		}
	}
}

func (m *HeartbeatMonitor) check(ctx context.Context) {
	// Find agents that were online but haven't reported recently,
	// and for which we haven't already created an offline alert in the last 10 minutes.
	rows, err := m.pool.Query(ctx,
		`SELECT id::text, hostname,
		        COALESCE(array_to_string(ip_addresses, ', '), '')
		 FROM agents
		 WHERE status = 'online'
		   AND last_seen < NOW() - $1::INTERVAL
		   AND id NOT IN (
		       SELECT DISTINCT agent_id FROM alerts
		       WHERE title LIKE 'エージェントオフライン%'
		         AND created_at > NOW() - INTERVAL '10 minutes'
		         AND agent_id IS NOT NULL
		   )
		 LIMIT 20`,
		fmt.Sprintf("%.0f seconds", m.offlineThreshold.Seconds()),
	)
	if err != nil {
		fail(ctx, err, "ハートビートチェック失敗")
		return
	}
	defer rows.Close()

	for rows.Next() {
		var id, hostname, ip string
		if err := rows.Scan(&id, &hostname, &ip); err != nil {
			continue
		}
		m.createOfflineAlert(ctx, id, hostname, ip)
		m.markAgentOffline(ctx, id)
	}
	if err := rows.Err(); err != nil {
		fail(ctx, err, "ハートビート切れエージェントの走査が途中で終わりました。オフライン通知が出ないエージェントがあります")
	}
}

func (m *HeartbeatMonitor) createOfflineAlert(ctx context.Context, agentID, hostname, ip string) {
	title := fmt.Sprintf("エージェントオフライン: %s", hostname)
	desc := fmt.Sprintf("エージェント %s (%s) が %s 以上ハートビートを送信していません。",
		hostname, ip, m.offlineThreshold)

	_, err := m.pool.Exec(ctx,
		`INSERT INTO alerts (agent_id, title, description, severity, status)
		 VALUES ($1, $2, $3, 8, 'open')`,
		agentID, title, desc,
	)
	if err != nil {
		fail(ctx, err, "オフラインアラートの作成に失敗しました", "agent_id", agentID)
		return
	}
	slog.Info("エージェントオフラインアラート作成", "agent_id", agentID, "hostname", hostname)
}

func (m *HeartbeatMonitor) markAgentOffline(ctx context.Context, agentID string) {
	// **書けないと、落ちている端末が画面では「オンライン」のままです。**
	if _, err := m.pool.Exec(ctx,
		`UPDATE agents SET status='offline', updated_at=NOW() WHERE id=$1`, agentID); err != nil {
		fail(ctx, err, "エージェントをオフラインにできませんでした", "agent_id", agentID)
	}
}
