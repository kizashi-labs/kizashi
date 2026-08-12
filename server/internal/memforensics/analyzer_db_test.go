package memforensics

// DetectInjection / DetectReflectiveLoad は events を、GetArtifacts は
// memory_artifacts を引く。events の実際の列は event_id / time で、
// id / created_at は存在しない。間隔式を ($1 || ' hours')::interval で組むと
// $1 が text 推論され、pgx が int の hours をエンコードできない。
// いずれもエラーは空スライスに変換されるため「検出 0 件」としか見えない。

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func memTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping DB-backed memforensics tests")
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatalf("connect test DB: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func cleanupEvents(t *testing.T, pool *pgxpool.Pool, agentID string) {
	t.Helper()
	ctx := context.Background()
	del := func() { _, _ = pool.Exec(ctx, `DELETE FROM events WHERE agent_id = $1`, agentID) }
	del()
	t.Cleanup(del)
}

// TestDetectInjection_FindsSuspiciousParent は svchost.exe が services.exe 以外から
// 起動されたケース (プロセスインジェクションの典型) を拾えることを見る。
func TestDetectInjection_FindsSuspiciousParent(t *testing.T) {
	pool := memTestPool(t)
	ctx := context.Background()
	const agentID = "b0b0b0b0-0000-4000-8000-000000000001"
	cleanupEvents(t, pool, agentID)

	if _, err := pool.Exec(ctx, `
		INSERT INTO events (time, agent_id, event_type, raw_data)
		VALUES (NOW() - INTERVAL '5 minutes', $1::uuid, 'process', $2::jsonb)`,
		agentID, `{
			"process_name":        "svchost.exe",
			"parent_process_name": "winword.exe",
			"pid":                 4242,
			"cmdline":             "svchost.exe -k netsvcs"
		}`); err != nil {
		t.Fatalf("seed event: %v", err)
	}

	a := NewAnalyzer(pool)
	artifacts, err := a.DetectInjection(ctx, 24)
	if err != nil {
		t.Fatalf("DetectInjection: %v", err)
	}

	// id / created_at を参照していた頃はクエリが落ちて常に空だった。
	var found *MemoryArtifact
	for _, art := range artifacts {
		if art.AgentID == agentID {
			found = art
			break
		}
	}
	if found == nil {
		t.Fatalf("投入した svchost.exe イベントが検出されていない (検出総数 %d)", len(artifacts))
	}
	if found.ProcessName != "svchost.exe" {
		t.Errorf("ProcessName = %q, want svchost.exe", found.ProcessName)
	}
	if found.PID != 4242 {
		t.Errorf("PID = %d, want 4242", found.PID)
	}
	if found.DetectedAt.IsZero() {
		t.Error("DetectedAt がゼロ値。events.time を引けていない")
	}
}

// TestDetectInjection_HoursWindowApplies は hours 引数が効くことを見る。
func TestDetectInjection_HoursWindowApplies(t *testing.T) {
	pool := memTestPool(t)
	ctx := context.Background()
	const agentID = "b0b0b0b0-0000-4000-8000-000000000002"
	cleanupEvents(t, pool, agentID)

	// 48 時間前 = 24h 窓の外、72h 窓の中。
	if _, err := pool.Exec(ctx, `
		INSERT INTO events (time, agent_id, event_type, raw_data)
		VALUES (NOW() - INTERVAL '48 hours', $1::uuid, 'process',
		        '{"process_name":"svchost.exe","parent_process_name":"excel.exe","pid":7}'::jsonb)`,
		agentID); err != nil {
		t.Fatalf("seed: %v", err)
	}

	a := NewAnalyzer(pool)
	countFor := func(hours int) int {
		t.Helper()
		arts, err := a.DetectInjection(ctx, hours)
		if err != nil {
			t.Fatalf("DetectInjection(%dh): %v", hours, err)
		}
		var n int
		for _, art := range arts {
			if art.AgentID == agentID {
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

// TestDetectReflectiveLoad_QueryRuns は同じ列名・間隔の取り違えが
// DetectReflectiveLoad 側にも無いことを確認する。
func TestDetectReflectiveLoad_QueryRuns(t *testing.T) {
	pool := memTestPool(t)
	ctx := context.Background()

	a := NewAnalyzer(pool)
	for _, hours := range []int{1, 24, 168} {
		arts, err := a.DetectReflectiveLoad(ctx, hours)
		if err != nil {
			t.Fatalf("DetectReflectiveLoad(%dh): %v", hours, err)
		}
		if arts == nil {
			t.Errorf("DetectReflectiveLoad(%dh) が nil を返した。空スライスを期待している", hours)
		}
	}
}

// TestGetArtifacts_QueryRuns は memory_artifacts 側の間隔式を確認する。
// events とは別テーブルだが、($1 || ' hours')::interval の取り違えは同じだった。
func TestGetArtifacts_QueryRuns(t *testing.T) {
	pool := memTestPool(t)
	ctx := context.Background()

	a := NewAnalyzer(pool)
	for _, hours := range []int{1, 24, 168} {
		arts, err := a.GetArtifacts(ctx, "", hours)
		if err != nil {
			t.Fatalf("GetArtifacts(%dh): %v", hours, err)
		}
		if arts == nil {
			t.Errorf("GetArtifacts(%dh) が nil を返した。空スライスを期待している", hours)
		}
	}

	// agentID 指定時は $2 が増える。プレースホルダの番号がずれていないことも見る。
	if _, err := a.GetArtifacts(ctx, "b0b0b0b0-0000-4000-8000-000000000003", 24); err != nil {
		t.Fatalf("GetArtifacts(agentID 指定): %v", err)
	}
}
