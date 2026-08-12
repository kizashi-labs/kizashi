package store_test

// テストが 1 本も無かった store メソッドの動作確認。
//
// いずれも実 DB に対して一度も実行されておらず、列名やプレースホルダの誤りが
// 混入しても気づけない状態だった。書き込み系は投入 → 実行 → 読み戻しで確認する。

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/edr-platform/server/internal/store"
)

func uncoveredTestDB(t *testing.T) *store.DB {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping DB-backed store tests")
	}
	db, err := store.Connect(context.Background(), url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)
	return db
}

func uncoveredTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	return uncoveredTestDB(t).Pool()
}

// seedAgent は対象エージェントを 1 台用意する。
func seedAgent(t *testing.T, db *store.DB, agentID string) {
	t.Helper()
	ctx := context.Background()

	cleanup := func() { _, _ = db.Pool().Exec(ctx, `DELETE FROM agents WHERE id=$1`, agentID) }
	cleanup()
	t.Cleanup(cleanup)

	if err := store.NewAgentStore(db).UpsertAgent(ctx, &store.AgentRow{
		ID: agentID, Hostname: "store-itest-host", OSType: "linux",
		OSVersion: "22.04", AgentVersion: "1.0.0",
		IPAddresses: []string{"10.7.7.7"}, Status: "online",
	}); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}
}

// ── AgentStore.UpdateMetrics ─────────────────────────────────────

func TestAgentStore_UpdateMetrics(t *testing.T) {
	db := uncoveredTestDB(t)
	ctx := context.Background()
	const agentID = "dd0dd0dd-0000-4000-8000-000000000001"
	seedAgent(t, db, agentID)

	s := store.NewAgentStore(db)
	if err := s.UpdateMetrics(ctx, agentID, 83.5, 4096); err != nil {
		t.Fatalf("UpdateMetrics: %v", err)
	}

	var cpu, mem float64
	if err := db.Pool().QueryRow(ctx,
		`SELECT cpu_usage, memory_usage_mb FROM agents WHERE id=$1`, agentID).Scan(&cpu, &mem); err != nil {
		t.Fatalf("読み戻し: %v", err)
	}
	if cpu != 83.5 || mem != 4096 {
		t.Errorf("(cpu, mem) = (%v, %v), want (83.5, 4096)", cpu, mem)
	}
}

// ── AgentStore.AgentBelongsToTenant ──────────────────────────────

func TestAgentStore_AgentBelongsToTenant(t *testing.T) {
	db := uncoveredTestDB(t)
	ctx := context.Background()
	const agentID = "dd0dd0dd-0000-4000-8000-000000000002"
	seedAgent(t, db, agentID)

	s := store.NewAgentStore(db)

	// 実際に紐づくテナント ID を読み出して突き合わせる。
	var tenantID *string
	if err := db.Pool().QueryRow(ctx,
		`SELECT tenant_id::text FROM agents WHERE id=$1`, agentID).Scan(&tenantID); err != nil {
		t.Fatalf("tenant_id 取得: %v", err)
	}

	if tenantID != nil {
		ok, err := s.AgentBelongsToTenant(ctx, agentID, *tenantID)
		if err != nil {
			t.Fatalf("AgentBelongsToTenant: %v", err)
		}
		if !ok {
			t.Errorf("自身のテナントに属していないと判定された (tenant=%s)", *tenantID)
		}
	}

	// 別テナントには属さない。ここが常に true だとテナント分離が破れる。
	ok, err := s.AgentBelongsToTenant(ctx, agentID, "dd0dd0dd-0000-4000-8000-0000000000ff")
	if err != nil {
		t.Fatalf("AgentBelongsToTenant(別テナント): %v", err)
	}
	if ok {
		t.Error("別テナントに属していると判定された")
	}
}

// IOCStore.TopHits はここでは対象にしていない。
// 実行すると `column a.src_ip does not exist` で必ず失敗する:
// alerts に src_ip / dst_ip / file_hash / domain の各列は存在せず、
// アラートのペイロードは raw_event (text) に入っている。
// 「何をもって IOC のヒットとするか」(alerts と events のどちらを、どの列で
// 突き合わせるか) は設計判断が要るため、推測で直さずバグとして報告する。

// ── CmdQueueStore.Cancel ─────────────────────────────────────────

func TestCmdQueueStore_Cancel(t *testing.T) {
	pool := uncoveredTestPool(t)
	ctx := context.Background()
	s := store.NewCmdQueueStore(pool)

	// 存在しない ID のキャンセルはエラーになる（黙って成功してはいけない）。
	if err := s.Cancel(ctx, "dd0dd0dd-0000-4000-8000-0000000000fe"); err == nil {
		t.Error("存在しないコマンドのキャンセルが成功している")
	}
}

// ── FIMRuleStore.Toggle ──────────────────────────────────────────

func TestFIMRuleStore_Toggle(t *testing.T) {
	pool := uncoveredTestPool(t)
	ctx := context.Background()
	s := store.NewFIMRuleStore(pool)

	created, err := s.Create(ctx, store.CreateFIMRuleInput{
		Name: "store-itest-fim-rule",
		Path: "/etc/store-itest",
	})
	if err != nil {
		t.Skipf("FIM ルールを作成できないためスキップ: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM fim_rules WHERE id=$1`, created.ID) })

	before := created.Enabled
	toggled, err := s.Toggle(ctx, created.ID)
	if err != nil {
		t.Fatalf("Toggle: %v", err)
	}
	if toggled.Enabled == before {
		t.Errorf("Toggle 後も enabled=%v のまま", before)
	}

	// 2 回目で元に戻る。
	again, err := s.Toggle(ctx, created.ID)
	if err != nil {
		t.Fatalf("Toggle(2回目): %v", err)
	}
	if again.Enabled != before {
		t.Errorf("2 回 Toggle しても元に戻っていない: %v -> %v", before, again.Enabled)
	}
}
