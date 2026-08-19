package store

import (
	"strings"
	"testing"
	"time"
)

// ─── NotificationHistoryEntry 構造体テスト ────────────────────────────────────

// TestNotificationHistoryEntry_ZeroValue は NotificationHistoryEntry のゼロ値を確認する
func TestNotificationHistoryEntry_ZeroValue(t *testing.T) {
	var e NotificationHistoryEntry
	if e.ID != "" {
		t.Errorf("ID のデフォルト = %q, want \"\"", e.ID)
	}
	if e.ChannelID != "" {
		t.Errorf("ChannelID のデフォルト = %q, want \"\"", e.ChannelID)
	}
	if e.Status != "" {
		t.Errorf("Status のデフォルト = %q, want \"\"", e.Status)
	}
	if e.ErrorMsg != "" {
		t.Errorf("ErrorMsg のデフォルト = %q, want \"\"", e.ErrorMsg)
	}
	if !e.SentAt.IsZero() {
		t.Errorf("SentAt のデフォルトはゼロ時刻であるべき: got %v", e.SentAt)
	}
}

// TestNotificationHistoryEntry_StatusValues は通知ステータスの有効な値を確認する
func TestNotificationHistoryEntry_StatusValues(t *testing.T) {
	// notification_history テーブルで使用されるステータス値
	validStatuses := []string{"sent", "failed"}
	for _, status := range validStatuses {
		e := NotificationHistoryEntry{Status: status}
		if e.Status != status {
			t.Errorf("Status = %q, want %q", e.Status, status)
		}
	}
}

// TestNotificationHistoryEntry_IsSent は通知成功ステータスの判定を確認する
func TestNotificationHistoryEntry_IsSent(t *testing.T) {
	cases := []struct {
		status string
		isSent bool
	}{
		{"sent", true},
		{"failed", false},
		{"", false},
		{"pending", false},
	}
	for _, tc := range cases {
		e := NotificationHistoryEntry{Status: tc.status}
		got := e.Status == "sent"
		if got != tc.isSent {
			t.Errorf("Status %q: isSent = %v, want %v", tc.status, got, tc.isSent)
		}
	}
}

// TestNotificationHistoryEntry_ChannelTypes はチャンネルタイプが正しく格納されることを確認する
func TestNotificationHistoryEntry_ChannelTypes(t *testing.T) {
	// EDR プラットフォームで使用される通知チャンネルタイプ
	channelTypes := []string{"email", "slack", "webhook", "teams", "pagerduty"}
	for _, channelType := range channelTypes {
		e := NotificationHistoryEntry{ChannelType: channelType}
		if e.ChannelType != channelType {
			t.Errorf("ChannelType = %q, want %q", e.ChannelType, channelType)
		}
	}
}

// TestNotificationHistoryEntry_FieldAssignment は全フィールドの代入を確認する
func TestNotificationHistoryEntry_FieldAssignment(t *testing.T) {
	sentAt := time.Now()
	e := NotificationHistoryEntry{
		ID:          "notif-001",
		ChannelID:   "channel-abc",
		ChannelName: "セキュリティアラート Slack",
		ChannelType: "slack",
		Subject:     "重大なアラート検出",
		Body:        "エージェント endpoint-01 で不審なプロセスが検出されました",
		Status:      "sent",
		ErrorMsg:    "",
		SentAt:      sentAt,
	}

	if e.ID != "notif-001" {
		t.Errorf("ID = %q, want \"notif-001\"", e.ID)
	}
	if e.ChannelType != "slack" {
		t.Errorf("ChannelType = %q, want \"slack\"", e.ChannelType)
	}
	if e.Status != "sent" {
		t.Errorf("Status = %q, want \"sent\"", e.Status)
	}
	if !e.SentAt.Equal(sentAt) {
		t.Errorf("SentAt = %v, want %v", e.SentAt, sentAt)
	}
}

// TestNotificationHistoryEntry_FailedWithErrorMsg は失敗エントリにエラーメッセージが含まれることを確認する
func TestNotificationHistoryEntry_FailedWithErrorMsg(t *testing.T) {
	e := NotificationHistoryEntry{
		Status:   "failed",
		ErrorMsg: "SMTP 接続がタイムアウトしました",
	}
	if e.Status != "failed" {
		t.Errorf("Status = %q, want \"failed\"", e.Status)
	}
	if e.ErrorMsg == "" {
		t.Error("failed ステータスのエントリはエラーメッセージを持つべき")
	}
	if !strings.Contains(e.ErrorMsg, "タイムアウト") {
		t.Errorf("ErrorMsg にタイムアウト情報が含まれるべき: got %q", e.ErrorMsg)
	}
}

// ─── 通知統計ロジックテスト ────────────────────────────────────────────────────

// 集計は **SQL の中**にあります（`COUNT(*) FILTER (WHERE status='sent')`）。
// ここには同じ集計を Go で書き直したヘルパーと、その3本の検査が置いて
// ありました。**Go の写しをいくら試しても、SQL 側は無傷のまま壊せます** ——
// `status='sent'` を `status='send'` と書き間違えても緑のままです。
//
// 本物を試す検査は `notification_stats_db_test.go` に移しました。
// **写しを消すだけにはしません** —— 消すと、その集計を試している検査が
// 1本も無くなります。

// ─── 通知フィルタービルダーテスト ─────────────────────────────────────────────

// ページの切り詰めは **`internal/api/handlers` にあります**
// （`page < 1 → 1`、`per_page < 1 || > 200 → 50`）。ここには
// `buildNotificationFilter` という写しが置いてありましたが、**値が
// 違いました** —— 既定 20（本物は 50）、200 超は 200 に丸める（本物は 50 に
// 戻す）。検査は、製品に無い約束を確かめていました。
//
// 本物を試す検査は `internal/api/handlers/notification_history_paging_test.go`
// にあります。`internal/store` の `List` は切り詰めません —— **切り詰めは
// 1箇所だけにします。** 2箇所に置くと、片方を直したときにもう片方が
// 残ります。
