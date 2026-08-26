package store_test

// NotificationHistoryStore.Stats は日数を int で受け取る。SQL 側で
// `($1 || ' days')::INTERVAL` と組むと $1 が text 推論され、pgx が int を
// text OID にエンコードできず ("unable to encode N into text format")
// クエリが毎回失敗する。エラーは握りつぶされるため、送信統計が 0 件固定に
// 見えるだけで原因が分からない。make_interval(days => $1) で int 文脈に統一
// してあることを実 DB で確認する。

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/edr-platform/server/internal/store"
)

func statsTestDB(t *testing.T) *store.DB {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping DB-backed store tests")
	}
	db, err := store.Connect(context.Background(), url)
	if err != nil {
		t.Fatalf("connect test DB: %v", err)
	}
	t.Cleanup(db.Close)
	return db
}

func TestNotificationHistoryStore_Stats_CountsRecentSends(t *testing.T) {
	db := statsTestDB(t)
	ctx := context.Background()
	s := store.NewNotificationHistoryStore(db)

	const channel = "stats-regression-channel"
	cleanup := func() {
		_, _ = db.Pool().Exec(ctx,
			`DELETE FROM notification_history WHERE channel_name = $1`, channel)
	}
	cleanup()
	t.Cleanup(cleanup)

	before, err := s.Stats(ctx, 7)
	if err != nil {
		t.Fatalf("Stats (投入前): %v", err)
	}
	baseSent := toInt(t, before["sent"])
	baseFailed := toInt(t, before["failed"])

	// 直近 7 日窓の中に sent 3 件 / failed 2 件。
	if _, err := db.Pool().Exec(ctx, `
		INSERT INTO notification_history (channel_name, channel_type, subject, body, status, sent_at)
		SELECT $1, 'webhook', 'subj', 'body', 'sent', NOW() - INTERVAL '1 day'
		FROM generate_series(1, 3)`, channel); err != nil {
		t.Fatalf("seed sent: %v", err)
	}
	if _, err := db.Pool().Exec(ctx, `
		INSERT INTO notification_history (channel_name, channel_type, subject, body, status, sent_at)
		SELECT $1, 'webhook', 'subj', 'body', 'failed', NOW() - INTERVAL '2 days'
		FROM generate_series(1, 2)`, channel); err != nil {
		t.Fatalf("seed failed: %v", err)
	}

	after, err := s.Stats(ctx, 7)
	if err != nil {
		t.Fatalf("Stats (投入後): %v", err)
	}

	// 間隔の組み立てを誤ると両方 0 のまま動かない。
	if got := toInt(t, after["sent"]); got < baseSent+3 {
		t.Errorf("sent = %d, want >= %d", got, baseSent+3)
	}
	if got := toInt(t, after["failed"]); got < baseFailed+2 {
		t.Errorf("failed = %d, want >= %d", got, baseFailed+2)
	}

	// by_channel も同じ間隔式を使う。投入したチャネルが現れること。
	byChannel, ok := after["by_channel"]
	if !ok {
		t.Fatalf("by_channel が返っていない: %v", after)
	}
	if !containsChannel(byChannel, channel) {
		t.Errorf("by_channel に %q が無い: %v", channel, byChannel)
	}
}

// TestNotificationHistoryStore_Stats_ExcludesOutsideWindow は日数窓が効くことを見る。
func TestNotificationHistoryStore_Stats_ExcludesOutsideWindow(t *testing.T) {
	db := statsTestDB(t)
	ctx := context.Background()
	s := store.NewNotificationHistoryStore(db)

	const channel = "stats-window-channel"
	cleanup := func() {
		_, _ = db.Pool().Exec(ctx,
			`DELETE FROM notification_history WHERE channel_name = $1`, channel)
	}
	cleanup()
	t.Cleanup(cleanup)

	before, err := s.Stats(ctx, 7)
	if err != nil {
		t.Fatalf("Stats (投入前): %v", err)
	}
	baseSent := toInt(t, before["sent"])

	// 30 日前 = 7 日窓の外。
	if _, err := db.Pool().Exec(ctx, `
		INSERT INTO notification_history (channel_name, channel_type, subject, body, status, sent_at)
		VALUES ($1, 'webhook', 'subj', 'body', 'sent', NOW() - INTERVAL '30 days')`, channel); err != nil {
		t.Fatalf("seed: %v", err)
	}

	after, err := s.Stats(ctx, 7)
	if err != nil {
		t.Fatalf("Stats (投入後): %v", err)
	}
	if got := toInt(t, after["sent"]); got != baseSent {
		t.Errorf("7 日窓の sent = %d, want %d (30 日前の行を拾ってはいけない)", got, baseSent)
	}

	// 60 日窓なら拾う。
	wide, err := s.Stats(ctx, 60)
	if err != nil {
		t.Fatalf("Stats(60d): %v", err)
	}
	if toInt(t, wide["sent"]) <= toInt(t, after["sent"]) {
		t.Errorf("60 日窓の sent = %v, 7 日窓 (%v) より多いはず",
			wide["sent"], after["sent"])
	}
}

func toInt(t *testing.T, v interface{}) int {
	t.Helper()
	n, ok := v.(int)
	if !ok {
		t.Fatalf("int でない値: %T (%v)", v, v)
	}
	return n
}

// containsChannel は by_channel にチャネル名が現れるかを見る。要素型
// (channelRow) は store 側の非公開型なので、文字列表現で突き合わせる。
// ここで見たいのは「集計クエリが動いて行が返ったか」であり、型ではない。
func containsChannel(byChannel interface{}, name string) bool {
	return strings.Contains(fmt.Sprintf("%v", byChannel), name)
}
