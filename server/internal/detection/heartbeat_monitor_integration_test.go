package detection

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// detectionTestPool は TEST_DATABASE_URL が設定されていれば接続プールを返し、
// 未設定なら統合テストをスキップする（scheduler の統合テストと同方式）。
// ローカルでは `make coverage`（一時 PostgreSQL 自動起動）で TEST_DATABASE_URL が渡る。
func detectionTestPool(t *testing.T) *pgxpool.Pool {
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

// recordingAlertSaver は SaveAlert されたホスト名を記録するだけの AlertSaver。
// DB へ書かないので、checkOnce のクエリ内にある重複抑止（直近10分の
// 「オフライン」アラート）がテスト間で干渉しない。
type recordingAlertSaver struct {
	mu        sync.Mutex
	hostnames []string
}

func (r *recordingAlertSaver) SaveAlert(_ context.Context, alert *StoredAlert) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hostnames = append(r.hostnames, alert.Hostname)
	return nil
}

func (r *recordingAlertSaver) saved() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.hostnames))
	copy(out, r.hostnames)
	return out
}

// TestHeartbeatMonitor_SkipsInactiveAgents は checkOnce が status='inactive' の
// エージェントにオフラインアラートを出さないことを検証する。
//
// 回帰の内容: DeadAgentCleanup は 30日以上未確認のエージェントを 'inactive' へ
// 遷移させる（migration 315/330 で CHECK に追加済み）。checkOnce の除外語彙が
// ('isolated','offline') のままだと、退役済みホストが「たった今オフラインになった」
// と再判定される。クエリ内の重複抑止は 10 分窓しか無く、既定チェック間隔は 2 分な
// ので、退役ホスト 1 台につき severity 7 のアラートが約10分ごとに無期限で生成される。
// scheduler.HeartbeatMonitor は status='online' の行しか更新しないため 'inactive' は
// 元に戻らず、この状態は自然解消しない。
func TestHeartbeatMonitor_SkipsInactiveAgents(t *testing.T) {
	pool := detectionTestPool(t)
	ctx := context.Background()

	// 他テスト・既存データと衝突しないユニークなホスト名マーカー
	marker := fmt.Sprintf("hbtest-%d", time.Now().UnixNano())
	hInactive := marker + "-inactive" // 退役済み → アラート不可
	hOnline := marker + "-online"     // 応答なし → アラートすべき
	hIsolated := marker + "-isolated" // 隔離中 → アラート不可

	insert := func(hostname, status string, lastSeen time.Time) {
		t.Helper()
		if _, err := pool.Exec(ctx,
			`INSERT INTO agents (hostname, os_type, status, last_seen)
			 VALUES ($1, 'linux', $2, $3)`,
			hostname, status, lastSeen,
		); err != nil {
			t.Fatalf("エージェント投入に失敗 (%s/%s): %v", hostname, status, err)
		}
	}

	insert(hInactive, "inactive", time.Now().Add(-40*24*time.Hour))
	insert(hOnline, "online", time.Now().Add(-1*time.Hour))
	insert(hIsolated, "isolated", time.Now().Add(-40*24*time.Hour))

	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM agents WHERE hostname LIKE $1`, marker+"%")
	})

	saver := &recordingAlertSaver{}
	NewHeartbeatMonitorWithConfig(pool, saver, 5, 2).checkOnce(ctx)

	// 本テストが投入した行だけを見る（DB には他テストの残骸があり得る）
	var got []string
	for _, h := range saver.saved() {
		if strings.HasPrefix(h, marker) {
			got = append(got, h)
		}
	}

	if len(got) != 1 || got[0] != hOnline {
		t.Errorf("アラート対象が想定と異なります: got=%v, want=[%s]", got, hOnline)
	}
	for _, h := range got {
		if h == hInactive {
			t.Error("status='inactive' の退役済みエージェントにオフラインアラートが出ました" +
				"（10分ごとの無期限量産に直結する回帰）")
		}
	}
}
