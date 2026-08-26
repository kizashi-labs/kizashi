package geoip

// GetThreatMapData は events を直接引く。events の時刻列は `time` (migration 002)
// で、`created_at` は存在しない。誤った列名のままだとクエリが毎回落ち、
// 呼び出し側には空スライスが返るため「脅威マップにデータが無い」としか見えない。
//
// 戻り値では区別できない (MaxMind DB を積んでいない環境では全 IP が "XX" に
// 落ちて、SQL が成功していても集計結果は空になる) ため、クエリ失敗時に出る
// slog の警告を捕まえて検証する。

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func threatMapPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping DB-backed geoip tests")
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatalf("connect test DB: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// lockedBuffer は slog の出力先。pgx が別 goroutine から書く可能性に備えて
// ミューテックスで保護する (-race 下での誤検知を避ける)。
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// captureWarnings は検証中の slog 出力を集める。
func captureWarnings(t *testing.T) *lockedBuffer {
	t.Helper()
	lb := &lockedBuffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(lb, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return lb
}

func TestGetThreatMapData_QuerySucceedsAgainstRealSchema(t *testing.T) {
	pool := threatMapPool(t)
	ctx := context.Background()
	const agentID = "f0f0f0f0-0000-4000-8000-000000000001"

	cleanup := func() {
		_, _ = pool.Exec(ctx, `DELETE FROM events WHERE agent_id = $1`, agentID)
	}
	cleanup()
	t.Cleanup(cleanup)

	if _, err := pool.Exec(ctx, `
		INSERT INTO events (time, agent_id, event_type, raw_data) VALUES
			(NOW() - INTERVAL '1 hour',  $1::uuid, 'network', '{"dst_ip":"8.8.8.8"}'::jsonb),
			(NOW() - INTERVAL '2 hours', $1::uuid, 'network', '{"dst_ip":"8.8.8.8"}'::jsonb),
			(NOW() - INTERVAL '3 hours', $1::uuid, 'network', '{"dst_ip":"1.1.1.1"}'::jsonb),
			(NOW() - INTERVAL '4 hours', $1::uuid, 'network', '{"note":"dst_ip なし"}'::jsonb)`,
		agentID); err != nil {
		t.Fatalf("seed events: %v", err)
	}

	logs := captureWarnings(t)

	l := NewLocator()
	entries, err := l.GetThreatMapData(ctx, pool, 24)
	if err != nil {
		t.Fatalf("GetThreatMapData: %v", err)
	}
	if entries == nil {
		t.Error("entries が nil。呼び出し側は空スライスを期待している")
	}

	// `created_at` を参照していた頃はここで必ず警告が出ていた
	// (column "created_at" does not exist)。
	if got := logs.String(); strings.Contains(got, "threat map query failed") {
		t.Errorf("脅威マップのクエリが失敗している:\n%s", got)
	}
}

// TestGetThreatMapData_HoursArgIsAccepted は hours 引数を変えても
// クエリが通ることを見る。間隔の組み立てを int/text で取り違えると
// pgx のエンコードで落ちるため、複数の値で通しておく。
func TestGetThreatMapData_HoursArgIsAccepted(t *testing.T) {
	pool := threatMapPool(t)
	ctx := context.Background()

	logs := captureWarnings(t)
	l := NewLocator()

	for _, hours := range []int{1, 24, 72, 168} {
		if _, err := l.GetThreatMapData(ctx, pool, hours); err != nil {
			t.Fatalf("GetThreatMapData(%dh): %v", hours, err)
		}
	}

	if got := logs.String(); strings.Contains(got, "threat map query failed") {
		t.Errorf("脅威マップのクエリが失敗している:\n%s", got)
	}
}
