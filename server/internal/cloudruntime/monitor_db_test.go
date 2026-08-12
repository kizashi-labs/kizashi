package cloudruntime

// DetectRuntimeThreats / GetRuntimeStats は events を直接引く。実スキーマの列は
// event_id / time (id / created_at は存在しない)。取り違えるとクエリが落ち、
// エラーは空スライスに変換されるため「検出 0 件」としか見えない。
// 間隔式も ($1 || ' hours')::interval だと $1 が text 推論され、pgx が int の
// hours をエンコードできず同じ症状になる。実 DB で確認する。

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func runtimeTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping DB-backed cloudruntime tests")
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatalf("connect test DB: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// seedMinerEvent は暗号通貨マイナーとして検出されるべきイベントを 1 件入れる。
func seedMinerEvent(t *testing.T, pool *pgxpool.Pool, agentID string) {
	t.Helper()
	ctx := context.Background()

	cleanup := func() {
		_, _ = pool.Exec(ctx, `DELETE FROM events WHERE agent_id = $1`, agentID)
	}
	cleanup()
	t.Cleanup(cleanup)

	if _, err := pool.Exec(ctx, `
		INSERT INTO events (time, agent_id, event_type, raw_data)
		VALUES (NOW() - INTERVAL '10 minutes', $1::uuid, 'process', $2::jsonb)`,
		agentID, `{
			"container_id":   "c0ffee",
			"container_name": "itest-container",
			"image_name":     "alpine:latest",
			"process_name":   "xmrig",
			"cmdline":        "xmrig --url stratum+tcp://pool.example:3333",
			"privileged":     false,
			"host_network":   false
		}`); err != nil {
		t.Fatalf("seed miner event: %v", err)
	}
}

func TestDetectRuntimeThreats_FindsSeededMiner(t *testing.T) {
	pool := runtimeTestPool(t)
	const agentID = "a0a0a0a0-0000-4000-8000-000000000001"
	seedMinerEvent(t, pool, agentID)

	m := NewMonitor(pool)
	threats, err := m.DetectRuntimeThreats(context.Background(), 24)
	if err != nil {
		t.Fatalf("DetectRuntimeThreats: %v", err)
	}

	// id / created_at を参照していた頃はクエリが落ちて常に空だった。
	var found *RuntimeThreat
	for _, th := range threats {
		if th.AgentID == agentID {
			found = th
			break
		}
	}
	if found == nil {
		t.Fatalf("投入した xmrig イベントが検出されていない (検出総数 %d)", len(threats))
	}
	if found.ThreatType != "crypto_mining" {
		t.Errorf("ThreatType = %q, want crypto_mining", found.ThreatType)
	}
	if found.ProcessName != "xmrig" {
		t.Errorf("ProcessName = %q, want xmrig", found.ProcessName)
	}
	if found.ID == "" {
		t.Error("ID が空。event_id を引けていない")
	}
	if found.DetectedAt.IsZero() {
		t.Error("DetectedAt がゼロ値。time を引けていない")
	}
}

// TestDetectRuntimeThreats_HoursWindowApplies は hours 引数が効くことを見る。
// 間隔式を text 文脈で組むと pgx のエンコードで落ちるため、複数の値で通す。
func TestDetectRuntimeThreats_HoursWindowApplies(t *testing.T) {
	pool := runtimeTestPool(t)
	const agentID = "a0a0a0a0-0000-4000-8000-000000000002"
	ctx := context.Background()

	cleanup := func() {
		_, _ = pool.Exec(ctx, `DELETE FROM events WHERE agent_id = $1`, agentID)
	}
	cleanup()
	t.Cleanup(cleanup)

	// 48 時間前 = 24h 窓の外、72h 窓の中。
	if _, err := pool.Exec(ctx, `
		INSERT INTO events (time, agent_id, event_type, raw_data)
		VALUES (NOW() - INTERVAL '48 hours', $1::uuid, 'process',
		        '{"process_name":"minerd","cmdline":"minerd -o stratum+tcp://x"}'::jsonb)`,
		agentID); err != nil {
		t.Fatalf("seed: %v", err)
	}

	m := NewMonitor(pool)
	countFor := func(hours int) int {
		t.Helper()
		threats, err := m.DetectRuntimeThreats(ctx, hours)
		if err != nil {
			t.Fatalf("DetectRuntimeThreats(%dh): %v", hours, err)
		}
		var n int
		for _, th := range threats {
			if th.AgentID == agentID {
				n++
			}
		}
		return n
	}

	if got := countFor(24); got != 0 {
		t.Errorf("24h 窓の検出数 = %d, want 0 (48h 前の 1 件のみ投入)", got)
	}
	if got := countFor(72); got != 1 {
		t.Errorf("72h 窓の検出数 = %d, want 1", got)
	}
}

func TestGetRuntimeStats_CountsSeededThreat(t *testing.T) {
	pool := runtimeTestPool(t)
	const agentID = "a0a0a0a0-0000-4000-8000-000000000003"

	m := NewMonitor(pool)
	before := m.GetRuntimeStats(context.Background())

	seedMinerEvent(t, pool, agentID)

	after := m.GetRuntimeStats(context.Background())
	if after.TotalThreats < before.TotalThreats+1 {
		t.Errorf("TotalThreats = %d, want >= %d (脅威 1 件投入後)",
			after.TotalThreats, before.TotalThreats+1)
	}
	if after.ContainersMonitored < before.ContainersMonitored {
		t.Errorf("ContainersMonitored が減っている: %d -> %d",
			before.ContainersMonitored, after.ContainersMonitored)
	}
}
