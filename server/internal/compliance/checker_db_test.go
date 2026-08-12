package compliance

// AssessAgent は agents と events を直接引く。実スキーマの列は
// agents.os_type (agents.os は存在しない) / events.time (events.created_at は
// 存在しない) で、いずれも取り違えると SQL が落ちる。agents 側の取り違えは
// AssessAgent 自体をエラーで終わらせ、events 側は握りつぶされて
// 「イベントが流れていない」という誤った判定になる。実 DB で確認する。

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func complianceTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping DB-backed compliance tests")
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatalf("connect test DB: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// seedAgentWithEvents は評価対象のエージェントと、直近 1 時間のイベントを用意する。
func seedAgentWithEvents(t *testing.T, pool *pgxpool.Pool, agentID string, events int) {
	t.Helper()
	ctx := context.Background()

	cleanup := func() {
		_, _ = pool.Exec(ctx, `DELETE FROM events WHERE agent_id = $1`, agentID)
		_, _ = pool.Exec(ctx, `DELETE FROM agents WHERE id = $1`, agentID)
	}
	cleanup()
	t.Cleanup(cleanup)

	if _, err := pool.Exec(ctx, `
		INSERT INTO agents (id, hostname, os_type, os_version, agent_version, status, last_seen)
		VALUES ($1::uuid, 'compliance-itest-host', 'windows', '11', '1.0.0', 'online', NOW())`,
		agentID); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	if events == 0 {
		return
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO events (time, agent_id, event_type, raw_data)
		SELECT NOW() - (g || ' minutes')::INTERVAL, $1::uuid, 'process',
		       '{"process_name":"msmpeng.exe"}'::jsonb
		FROM generate_series(1, $2) g`, agentID, events); err != nil {
		t.Fatalf("seed events: %v", err)
	}
}

func TestAssessAgent_ReadsAgentAndEvents(t *testing.T) {
	pool := complianceTestPool(t)
	const agentID = "c0c0c0c0-0000-4000-8000-000000000001"
	seedAgentWithEvents(t, pool, agentID, 5)

	c := NewChecker(pool)
	got, err := c.AssessAgent(context.Background(), agentID)
	if err != nil {
		t.Fatalf("AssessAgent: %v (agents.os_type を引けていない可能性がある)", err)
	}
	if got == nil {
		t.Fatal("AssessAgent が nil を返した")
	}

	// agents.os を参照していた頃はここまで到達せずエラーで抜けていた。
	if got.Hostname != "compliance-itest-host" {
		t.Errorf("Hostname = %q, want compliance-itest-host", got.Hostname)
	}
	if got.OS != "windows" {
		t.Errorf("OS = %q, want windows (os_type を引けていない)", got.OS)
	}

	// events.created_at を参照していた頃は eventsFlowing が常に false だった。
	byID := map[string]*ComplianceCheck{}
	for _, ck := range got.Checks {
		byID[ck.CheckID] = ck
	}
	for _, id := range []string{"events_flowing", "logging_enabled", "av_running"} {
		ck, ok := byID[id]
		if !ok {
			t.Fatalf("チェック %q が結果に無い", id)
		}
		if ck.Status != "pass" {
			t.Errorf("%s の status = %q, want pass (直近 1 時間に 5 件投入済み。evidence: %s)",
				id, ck.Status, ck.Evidence)
		}
	}
}

// TestAssessAgent_NoEventsFails は「本当にイベントが無い」場合に fail になることを見る。
// これが無いと、上のテストは常に pass を返す実装でも通ってしまう。
func TestAssessAgent_NoEventsFails(t *testing.T) {
	pool := complianceTestPool(t)
	const agentID = "c0c0c0c0-0000-4000-8000-000000000002"
	seedAgentWithEvents(t, pool, agentID, 0)

	c := NewChecker(pool)
	got, err := c.AssessAgent(context.Background(), agentID)
	if err != nil {
		t.Fatalf("AssessAgent: %v", err)
	}

	for _, ck := range got.Checks {
		if ck.CheckID == "events_flowing" && ck.Status == "pass" {
			t.Errorf("イベント 0 件なのに events_flowing = pass (evidence: %s)", ck.Evidence)
		}
	}
}
