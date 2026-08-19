package scheduler

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestResolveRecoveredSensorAlerts covers the auto-close for degraded-sensor
// alerts.
//
// The alert is a standing claim about the present ("this endpoint is blind"), not
// a record of a moment, and it dedups for 24h. Redeploying the agent fixes the
// endpoint but nothing used to touch the alert, so the queue kept asserting a
// degradation that no longer existed. An alarm still lit after the fix is how
// operators learn to ignore it — the exact outcome the 24h dedup exists to avoid.
func TestResolveRecoveredSensorAlerts(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping degraded sensor recovery test")
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	ctx := context.Background()

	// seedAgentWithSensorAlert creates an online agent in the given telemetry_mode
	// and an open degraded-sensor alert against it, and returns both IDs.
	seed := func(t *testing.T, hostname, mode, alertStatus string) (string, string) {
		t.Helper()
		var agentID string
		if err := pool.QueryRow(ctx,
			`INSERT INTO agents (hostname, os_type, status, last_seen, enrolled_at, telemetry_mode)
			 VALUES ($1, 'linux', 'online', NOW(), NOW(), $2) RETURNING id::text`,
			hostname, mode).Scan(&agentID); err != nil {
			t.Fatalf("seed agent: %v", err)
		}
		t.Cleanup(func() { _, _ = pool.Exec(ctx, "DELETE FROM agents WHERE id=$1", agentID) })

		var alertID string
		if err := pool.QueryRow(ctx,
			`INSERT INTO alerts (agent_id, title, description, severity, status)
			 VALUES ($1::uuid, $2, 'テスト', 5, $3) RETURNING id::text`,
			agentID, "エージェント "+hostname+degradedSensorTitleSuffix, alertStatus,
		).Scan(&alertID); err != nil {
			t.Fatalf("seed alert: %v", err)
		}
		t.Cleanup(func() { _, _ = pool.Exec(ctx, "DELETE FROM alerts WHERE id=$1", alertID) })
		return agentID, alertID
	}

	statusOf := func(t *testing.T, alertID string) string {
		t.Helper()
		var s string
		if err := pool.QueryRow(ctx, `SELECT status FROM alerts WHERE id=$1::uuid`, alertID).Scan(&s); err != nil {
			t.Fatalf("read status: %v", err)
		}
		return s
	}

	t.Run("復旧したエージェントのアラートは自動クローズされる", func(t *testing.T) {
		_, alertID := seed(t, "recov-ebpf", "ebpf", "open")
		NewAgentHealthAlerter(pool, nil).resolveRecoveredSensorAlerts(ctx)
		if got := statusOf(t, alertID); got != "auto_resolved" {
			t.Errorf("status = %q、期待 auto_resolved。"+
				"エージェントを再配備してセンサーが戻っても、キューに「検知能力低下」が"+
				"残り続けます", got)
		}
	})

	t.Run("まだ降格中のエージェントのアラートは残す", func(t *testing.T) {
		_, alertID := seed(t, "recov-still-poll", "poll", "open")
		NewAgentHealthAlerter(pool, nil).resolveRecoveredSensorAlerts(ctx)
		if got := statusOf(t, alertID); got != "open" {
			t.Errorf("status = %q、期待 open。まだ盲目な端末のアラートを消しています", got)
		}
	})

	// An analyst's verdict outranks the machine's. Only open/investigating are
	// eligible; anything already triaged keeps the human's decision.
	t.Run("担当者が既に処理したアラートは触らない", func(t *testing.T) {
		_, alertID := seed(t, "recov-fp", "ebpf", "false_positive")
		NewAgentHealthAlerter(pool, nil).resolveRecoveredSensorAlerts(ctx)
		if got := statusOf(t, alertID); got != "false_positive" {
			t.Errorf("status = %q、期待 false_positive。担当者の判断を上書きしています", got)
		}
	})

	t.Run("調査中のアラートは対象に含む", func(t *testing.T) {
		_, alertID := seed(t, "recov-investigating", "ebpf", "investigating")
		NewAgentHealthAlerter(pool, nil).resolveRecoveredSensorAlerts(ctx)
		if got := statusOf(t, alertID); got != "auto_resolved" {
			t.Errorf("status = %q、期待 auto_resolved", got)
		}
	})

	// The title suffix is the identity; the hostname in front of it is not.
	t.Run("他の種類のヘルスアラートは巻き込まない", func(t *testing.T) {
		var agentID string
		if err := pool.QueryRow(ctx,
			`INSERT INTO agents (hostname, os_type, status, last_seen, enrolled_at, telemetry_mode)
			 VALUES ('recov-cpu', 'linux', 'online', NOW(), NOW(), 'ebpf') RETURNING id::text`,
		).Scan(&agentID); err != nil {
			t.Fatalf("seed agent: %v", err)
		}
		t.Cleanup(func() { _, _ = pool.Exec(ctx, "DELETE FROM agents WHERE id=$1", agentID) })

		var alertID string
		if err := pool.QueryRow(ctx,
			`INSERT INTO alerts (agent_id, title, description, severity, status)
			 VALUES ($1::uuid, 'エージェント recov-cpu リソース逼迫', 'テスト', 5, 'open')
			 RETURNING id::text`, agentID).Scan(&alertID); err != nil {
			t.Fatalf("seed alert: %v", err)
		}
		t.Cleanup(func() { _, _ = pool.Exec(ctx, "DELETE FROM alerts WHERE id=$1", alertID) })

		NewAgentHealthAlerter(pool, nil).resolveRecoveredSensorAlerts(ctx)
		if got := statusOf(t, alertID); got != "open" {
			t.Errorf("status = %q、期待 open。センサー降格以外のアラートまで閉じています", got)
		}
	})
}
