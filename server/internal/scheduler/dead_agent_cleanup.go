package scheduler

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

// DeadAgentCleanup marks agents that haven't been seen for 30+ days as inactive
// and creates alerts for agents that have been offline for 24+ hours.
type DeadAgentCleanup struct {
	pool *pgxpool.Pool
	nc   *nats.Conn
}

func NewDeadAgentCleanup(pool *pgxpool.Pool, nc *nats.Conn) *DeadAgentCleanup {
	return &DeadAgentCleanup{pool: pool, nc: nc}
}

func (d *DeadAgentCleanup) Run(ctx context.Context) {
	// Run daily, first check after 5 minutes
	timer := time.NewTimer(5 * time.Minute)
	defer timer.Stop()
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			d.cleanup(ctx)
		case <-ticker.C:
			d.cleanup(ctx)
		}
	}
}

func (d *DeadAgentCleanup) cleanup(ctx context.Context) {
	// 1. Check if agents table exists
	var tableExists bool
	err := d.pool.QueryRow(ctx,
		`SELECT EXISTS (
			SELECT 1 FROM pg_tables
			WHERE schemaname = 'public' AND tablename = 'agents'
		)`,
	).Scan(&tableExists)
	if err != nil {
		slog.Error("デッドエージェントクリーンアップ: agentsテーブル確認失敗", "error", err)
		return
	}
	if !tableExists {
		slog.Debug("デッドエージェントクリーンアップ: agentsテーブルが存在しません。スキップします")
		return
	}

	// 2. Mark 30-day-inactive agents as inactive
	tag, err := d.pool.Exec(ctx,
		`UPDATE agents
		 SET status = 'inactive'
		 WHERE status = 'offline'
		   AND last_seen < NOW() - INTERVAL '30 days'`,
	)
	if err != nil {
		slog.Error("デッドエージェントクリーンアップ: 非アクティブ化クエリ失敗", "error", err)
	} else {
		count := tag.RowsAffected()
		if count > 0 {
			slog.Info("デッドエージェントクリーンアップ: 30日間オフラインのエージェントを非アクティブ化",
				"count", count)
		}
	}

	// 3. For extended-offline agents (>24h but <30 days), create dedup alerts
	rows, err := d.pool.Query(ctx,
		`SELECT id::text, hostname
		 FROM agents
		 WHERE status = 'offline'
		   AND last_seen < NOW() - INTERVAL '24 hours'
		   AND last_seen > NOW() - INTERVAL '30 days'
		 LIMIT 50`,
	)
	if err != nil {
		slog.Error("デッドエージェントクリーンアップ: 長時間オフラインエージェント取得失敗", "error", err)
		return
	}
	defer rows.Close()

	alertsCreated := 0
	for rows.Next() {
		var agentID, hostname string
		if err := rows.Scan(&agentID, &hostname); err != nil {
			slog.Warn("デッドエージェントクリーンアップ: 行スキャン失敗", "error", err)
			continue
		}

		// Check for existing dedup alert in last 24h
		var existingCount int
		err := d.pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM alerts
			 WHERE title LIKE '%agent offline%'
			   AND description LIKE '%' || $1 || '%'
			   AND created_at > NOW() - INTERVAL '24 hours'`,
			hostname,
		).Scan(&existingCount)
		if err != nil {
			slog.Warn("デッドエージェントクリーンアップ: 既存アラート確認失敗",
				"hostname", hostname, "error", err)
			continue
		}

		if existingCount > 0 {
			// Alert already exists within 24h, skip
			continue
		}

		// Insert new alert
		title := fmt.Sprintf("エージェント長時間オフライン: %s", hostname)
		desc := fmt.Sprintf("エージェント %s が24時間以上オフラインです。確認が必要です。", hostname)

		var alertID string
		err = d.pool.QueryRow(ctx,
			`INSERT INTO alerts (agent_id, title, description, severity, status)
			 VALUES ($1, $2, $3, 5, 'open')
			 RETURNING id::text`,
			agentID, title, desc,
		).Scan(&alertID)
		if err != nil {
			slog.Error("デッドエージェントクリーンアップ: アラート作成失敗",
				"hostname", hostname, "error", err)
			continue
		}

		alertsCreated++

		// Publish NATS alerts.new
		if d.nc != nil {
			payload := map[string]interface{}{
				"id":          alertID,
				"agent_id":    agentID,
				"title":       title,
				"description": desc,
				"severity":    5,
				"status":      "open",
			}
			data, _ := json.Marshal(payload)
			if pubErr := d.nc.Publish("alerts.new", data); pubErr != nil {
				slog.Warn("デッドエージェントクリーンアップ: NATSパブリッシュ失敗",
					"alert_id", alertID, "error", pubErr)
			}
		}
	}

	if alertsCreated > 0 {
		slog.Info("デッドエージェントクリーンアップ: 長時間オフラインアラート作成完了",
			"alerts_created", alertsCreated)
	}

	slog.Debug("デッドエージェントクリーンアップ: 完了")
}
