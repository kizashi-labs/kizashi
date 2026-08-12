package scheduler

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// schedulerTestPool は TEST_DATABASE_URL が設定されていれば接続プールを返し、
// 未設定なら統合テストをスキップする（既存 handlers 統合テストと同方式）。
// ローカルでは `make coverage`（一時 PostgreSQL 自動起動）で TEST_DATABASE_URL が渡る。
func schedulerTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("TEST_DATABASE_URL 未設定 — DB統合テストをスキップします")
	}
	pool, err := pgxpool.New(context.Background(), dbURL)
	if err != nil {
		t.Fatalf("DB接続に失敗: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// TestDeadAgentCleanup_Integration は cleanup() の実 DB 挙動を検証する:
//   - 30日以上オフライン → status='inactive' に更新
//   - 24時間〜30日オフライン → offline アラートを1件作成
//   - オンライン → 変更なし
func TestDeadAgentCleanup_Integration(t *testing.T) {
	pool := schedulerTestPool(t)
	ctx := context.Background()

	// 他テストと衝突しないユニークなホスト名マーカー
	marker := fmt.Sprintf("deadtest-%d", time.Now().UnixNano())
	hStale := marker + "-stale"   // 40日前 → inactive 化されるべき
	hOffline := marker + "-off"   // 25時間前 → アラート対象
	hOnline := marker + "-online" // 現在 → 不変

	var idStale, idOffline, idOnline string
	mustInsertAgent := func(hostname, status string, lastSeen time.Time) string {
		var id string
		err := pool.QueryRow(ctx,
			`INSERT INTO agents (hostname, os_type, status, last_seen)
			 VALUES ($1, 'linux', $2, $3) RETURNING id::text`,
			hostname, status, lastSeen,
		).Scan(&id)
		if err != nil {
			t.Fatalf("エージェント投入に失敗 (%s): %v", hostname, err)
		}
		return id
	}

	idStale = mustInsertAgent(hStale, "offline", time.Now().Add(-40*24*time.Hour))
	idOffline = mustInsertAgent(hOffline, "offline", time.Now().Add(-25*time.Hour))
	idOnline = mustInsertAgent(hOnline, "online", time.Now())

	// テスト後に投入データを片付ける
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM alerts WHERE agent_id = ANY($1::uuid[])`,
			[]string{idStale, idOffline, idOnline})
		_, _ = pool.Exec(ctx, `DELETE FROM agents WHERE id = ANY($1::uuid[])`,
			[]string{idStale, idOffline, idOnline})
	})

	// 実行
	d := NewDeadAgentCleanup(pool, nil) // nc=nil: NATS なしでもアラート DB 挿入は行われる
	d.cleanup(ctx)

	// 1) 40日オフライン → inactive
	var statusStale string
	if err := pool.QueryRow(ctx, `SELECT status FROM agents WHERE id=$1::uuid`, idStale).Scan(&statusStale); err != nil {
		t.Fatalf("stale エージェント状態の取得に失敗: %v", err)
	}
	if statusStale != "inactive" {
		t.Errorf("30日以上オフラインのエージェントは inactive になるべき: got %q", statusStale)
	}

	// 2) 25時間オフライン → アラート1件（agent_id 紐付け）
	var alertCount int
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM alerts WHERE agent_id=$1::uuid`, idOffline,
	).Scan(&alertCount); err != nil {
		t.Fatalf("アラート件数の取得に失敗: %v", err)
	}
	if alertCount != 1 {
		t.Errorf("24h〜30日オフラインのエージェントには1件のアラートが作られるべき: got %d", alertCount)
	}

	// 3) オンライン → 変更なし・アラートなし
	var statusOnline string
	if err := pool.QueryRow(ctx, `SELECT status FROM agents WHERE id=$1::uuid`, idOnline).Scan(&statusOnline); err != nil {
		t.Fatalf("online エージェント状態の取得に失敗: %v", err)
	}
	if statusOnline != "online" {
		t.Errorf("オンラインのエージェントは不変であるべき: got %q", statusOnline)
	}
	var onlineAlerts int
	_ = pool.QueryRow(ctx, `SELECT COUNT(*) FROM alerts WHERE agent_id=$1::uuid`, idOnline).Scan(&onlineAlerts)
	if onlineAlerts != 0 {
		t.Errorf("オンラインのエージェントにアラートは作られないべき: got %d", onlineAlerts)
	}
}

// TestDeadAgentCleanup_MissingTableIsSafe は agents テーブルが無くても panic せず
// 安全に return することを確認する（cleanup の存在チェック分岐）。
func TestDeadAgentCleanup_TableExistsGuard(t *testing.T) {
	pool := schedulerTestPool(t)
	// agents テーブルは存在するので cleanup は正常系を通る。
	// ここでは cleanup が nil NATS でも panic しないことを確認する（回帰ガード）。
	d := NewDeadAgentCleanup(pool, nil)
	d.cleanup(context.Background()) // panic せず戻ればOK
}
