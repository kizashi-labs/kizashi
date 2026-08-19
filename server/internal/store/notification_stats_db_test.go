package store_test

import (
	"context"
	"strings"
	"testing"

	"github.com/edr-platform/server/internal/store"
)

// 通知の成功/失敗の集計は **SQL の中**にあります:
//
//	COUNT(*) FILTER (WHERE status='sent')
//	COUNT(*) FILTER (WHERE status='failed')
//
// `notification_history_pure_test.go` には、同じ集計を Go で書き直した
// `calcNotificationStats` と、その3本の検査が置いてありました。
// **Go の写しをいくら試しても、SQL 側は無傷のまま壊せます** ——
// `status='sent'` を `status='send'` と書き間違えても緑のままです。
//
// この数字は通知履歴の画面に出ます。**失敗が 0 と出ることと、失敗を
// 数えられていないことが、同じ画面になります。**

func seedNotification(t *testing.T, db *store.DB, channel, status string) {
	t.Helper()
	s := store.NewNotificationHistoryStore(db)
	if err := s.Insert(context.Background(), &store.NotificationHistoryEntry{
		ChannelName: channel,
		ChannelType: "slack",
		Subject:     "probe",
		Body:        "probe",
		Status:      status,
	}); err != nil {
		t.Fatalf("Insert(%s): %v", status, err)
	}
}

func TestNotificationStatsCountsSentAndFailed(t *testing.T) {
	db := covTestDB(t)
	ctx := context.Background()
	const channel = "stats-probe-channel"

	t.Cleanup(func() {
		_, _ = db.Pool().Exec(ctx,
			"DELETE FROM notification_history WHERE channel_name = $1", channel)
	})
	_, _ = db.Pool().Exec(ctx,
		"DELETE FROM notification_history WHERE channel_name = $1", channel)

	s := store.NewNotificationHistoryStore(db)
	before, err := s.Stats(ctx, 7)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	sent0, failed0 := statInt(t, before, "sent"), statInt(t, before, "failed")

	for i := 0; i < 3; i++ {
		seedNotification(t, db, channel, "sent")
	}
	for i := 0; i < 2; i++ {
		seedNotification(t, db, channel, "failed")
	}

	after, err := s.Stats(ctx, 7)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if got := statInt(t, after, "sent") - sent0; got != 3 {
		t.Errorf("sent の増分 = %d, want 3", got)
	}
	if got := statInt(t, after, "failed") - failed0; got != 2 {
		t.Errorf("failed の増分 = %d, want 2。**失敗が 0 と出ることと、"+
			"失敗を数えられていないことが同じ画面になります**", got)
	}
}

// 数えられる状態が、DB 側で 'sent' と 'failed' に限られていること。
//
// **ここは「知らない status は数えない」を確かめるつもりで書きました。**
// 入れようとしたら CHECK 制約に弾かれました —— 数え漏れる第三の状態は、
// そもそも入りません。**確かめようとして、確かめる必要が無いと分かった**
// ので、その事実の方を留めます。制約が緩められたら、この検査が落ちて、
// 集計の側を見直す番だと分かります。
func TestOnlySentAndFailedCanBeStored(t *testing.T) {
	db := covTestDB(t)
	ctx := context.Background()

	var def string
	err := db.Pool().QueryRow(ctx,
		`SELECT pg_get_constraintdef(oid) FROM pg_constraint
		 WHERE conname = 'notification_history_status_check'`).Scan(&def)
	if err != nil {
		t.Fatalf("制約が見つかりません: %v。**集計は 'sent' と 'failed' しか"+
			"数えないので、他の値が入ると数字から静かに落ちます**", err)
	}
	for _, want := range []string{"sent", "failed"} {
		if !strings.Contains(def, "'"+want+"'") {
			t.Errorf("制約に %q がありません: %s", want, def)
		}
	}
	// 第三の状態が入れられないこと。
	s := store.NewNotificationHistoryStore(db)
	if err := s.Insert(ctx, &store.NotificationHistoryEntry{
		ChannelName: "stats-probe-unknown", Status: "pending",
	}); err == nil {
		_, _ = db.Pool().Exec(ctx,
			"DELETE FROM notification_history WHERE channel_name = 'stats-probe-unknown'")
		t.Error("'pending' が入りました。**集計はこれを数えないので、" +
			"送ったのに sent にも failed にも出ない通知ができます**")
	}
}

func statInt(t *testing.T, m map[string]interface{}, key string) int {
	t.Helper()
	v, ok := m[key]
	if !ok {
		t.Fatalf("Stats に %q がありません: %v", key, m)
	}
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	}
	t.Fatalf("%q の型が %T です", key, v)
	return 0
}
