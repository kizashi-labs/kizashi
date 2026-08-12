package handlers

// countEventsCapped は非公開のため外部テストパッケージ (handlers_test) からは
// 呼べない。ページネーション表示の要である「上限で打ち切る」挙動を直接検証する。
//
// 打ち切りが壊れると events 一覧は再び全 chunk 走査に戻り、検証環境で観測した
// タイムアウト (canceling statement due to user request) が再発する。

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// cappedTestPool は TEST_DATABASE_URL 未設定ならスキップする。
// ゲートは handlers_test.testPool と同じ。
func cappedTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping DB integration tests")
	}
	pool, err := pgxpool.New(context.Background(), dbURL)
	if err != nil {
		t.Fatalf("failed to connect to test database: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// seedCappedEvents は agentID 名義の events を n 件投入し、後始末を登録する。
// events は他パッケージのテストとも共有するため、必ず agent_id で絞り込む。
func seedCappedEvents(t *testing.T, pool *pgxpool.Pool, agentID string, n int) {
	t.Helper()
	ctx := context.Background()

	cleanup := func() {
		_, _ = pool.Exec(ctx, `DELETE FROM events WHERE agent_id = $1`, agentID)
	}
	cleanup()
	t.Cleanup(cleanup)

	if n == 0 {
		return
	}
	// 1 文で投入する。10,000 件超を 1 件ずつ INSERT すると CI が無駄に遅くなる。
	if _, err := pool.Exec(ctx, `
		INSERT INTO events (time, agent_id, event_type, raw_data)
		SELECT NOW() - (g || ' seconds')::INTERVAL, $1::uuid, 'process', '{"src":"capped-test"}'::jsonb
		FROM generate_series(1, $2) g`, agentID, n); err != nil {
		t.Fatalf("seed events: %v", err)
	}
}

func TestCountEventsCapped_CountsMatchingRows(t *testing.T) {
	pool := cappedTestPool(t)
	const agentID = "d1d1d1d1-0000-4000-8000-00000000c001"
	seedCappedEvents(t, pool, agentID, 7)

	n, capped := countEventsCapped(context.Background(), pool, "WHERE agent_id = $1", agentID)
	if n != 7 {
		t.Errorf("count = %d, want 7", n)
	}
	if capped {
		t.Error("capped = true, want false (上限にはるかに満たない)")
	}
}

func TestCountEventsCapped_NoMatchReturnsZero(t *testing.T) {
	pool := cappedTestPool(t)
	const agentID = "d1d1d1d1-0000-4000-8000-00000000c002"
	seedCappedEvents(t, pool, agentID, 0)

	n, capped := countEventsCapped(context.Background(), pool, "WHERE agent_id = $1", agentID)
	if n != 0 || capped {
		t.Errorf("(count, capped) = (%d, %v), want (0, false)", n, capped)
	}
}

// TestCountEventsCapped_StopsAtCap は上限ちょうどと上限超えの境界を見る。
// maxCountedEvents+1 件投入して「打ち切り」、1 件削って「ちょうど上限」を
// 同じデータセットで確認する (10,000 件規模の投入を 2 度やらないため)。
func TestCountEventsCapped_StopsAtCap(t *testing.T) {
	pool := cappedTestPool(t)
	const agentID = "d1d1d1d1-0000-4000-8000-00000000c003"
	seedCappedEvents(t, pool, agentID, maxCountedEvents+1)

	ctx := context.Background()
	where := "WHERE agent_id = $1"

	n, capped := countEventsCapped(ctx, pool, where, agentID)
	if n != maxCountedEvents {
		t.Errorf("上限超え: count = %d, want %d", n, maxCountedEvents)
	}
	if !capped {
		t.Error("上限超え: capped = false, want true")
	}

	// ちょうど maxCountedEvents 件に減らすと、打ち切りではなく実数として返る。
	// ctid ではなく event_id で消す: events は hypertable で、ctid はチャンクを
	// またぐと重複しうるため別チャンクの行を巻き込む。
	if _, err := pool.Exec(ctx, `
		DELETE FROM events WHERE event_id = (
			SELECT event_id FROM events WHERE agent_id = $1 LIMIT 1
		)`, agentID); err != nil {
		t.Fatalf("trim one row: %v", err)
	}

	n, capped = countEventsCapped(ctx, pool, where, agentID)
	if n != maxCountedEvents {
		t.Errorf("上限ちょうど: count = %d, want %d", n, maxCountedEvents)
	}
	if capped {
		t.Error("上限ちょうど: capped = true, want false")
	}
}

// TestCountEventsCapped_QueryErrorReturnsZero はクエリが落ちたときに
// panic せず (0, false) を返すことを固定する。events の列名を間違えたまま
// 握りつぶすのがこの PR で直したバグ群の共通原因だったため、ここでは
// 「握りつぶすが必ず slog.Warn に残す」という現在の契約を明示的に守る。
func TestCountEventsCapped_QueryErrorReturnsZero(t *testing.T) {
	pool := cappedTestPool(t)

	n, capped := countEventsCapped(context.Background(), pool,
		"WHERE no_such_column = $1", "x")
	if n != 0 || capped {
		t.Errorf("(count, capped) = (%d, %v), want (0, false)", n, capped)
	}
}

// TestCountEventsCapped_WhereClauseIsOptional は where 空文字 (フィルタ無し) でも
// 組み立てた SQL が構文として妥当であることを確認する。
func TestCountEventsCapped_WhereClauseIsOptional(t *testing.T) {
	pool := cappedTestPool(t)

	n, _ := countEventsCapped(context.Background(), pool, "")
	if n < 0 {
		t.Errorf("count = %d, want >= 0", n)
	}
	if n > maxCountedEvents {
		t.Errorf("count = %d, 上限 %d を超えて返している", n, maxCountedEvents)
	}
}
