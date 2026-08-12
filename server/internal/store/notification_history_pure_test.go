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

// calcNotificationStats は通知エントリの一覧から成功/失敗数を集計するヘルパー（テスト専用）
func calcNotificationStats(entries []*NotificationHistoryEntry) (sent int, failed int) {
	for _, e := range entries {
		switch e.Status {
		case "sent":
			sent++
		case "failed":
			failed++
		}
	}
	return sent, failed
}

// TestCalcNotificationStats_AllSent は全て成功したときの集計を確認する
func TestCalcNotificationStats_AllSent(t *testing.T) {
	entries := []*NotificationHistoryEntry{
		{Status: "sent"},
		{Status: "sent"},
		{Status: "sent"},
	}
	sent, failed := calcNotificationStats(entries)
	if sent != 3 {
		t.Errorf("sent = %d, want 3", sent)
	}
	if failed != 0 {
		t.Errorf("failed = %d, want 0", failed)
	}
}

// TestCalcNotificationStats_Mixed は成功と失敗が混在するときの集計を確認する
func TestCalcNotificationStats_Mixed(t *testing.T) {
	entries := []*NotificationHistoryEntry{
		{Status: "sent"},
		{Status: "failed"},
		{Status: "sent"},
		{Status: "failed"},
		{Status: "sent"},
	}
	sent, failed := calcNotificationStats(entries)
	if sent != 3 {
		t.Errorf("sent = %d, want 3", sent)
	}
	if failed != 2 {
		t.Errorf("failed = %d, want 2", failed)
	}
}

// TestCalcNotificationStats_Empty は空のエントリリストが 0 を返すことを確認する
func TestCalcNotificationStats_Empty(t *testing.T) {
	sent, failed := calcNotificationStats([]*NotificationHistoryEntry{})
	if sent != 0 {
		t.Errorf("空リストの sent = %d, want 0", sent)
	}
	if failed != 0 {
		t.Errorf("空リストの failed = %d, want 0", failed)
	}
}

// ─── 通知フィルタービルダーテスト ─────────────────────────────────────────────

// buildNotificationFilter はページネーション用パラメータを検証するヘルパー（テスト専用）
func buildNotificationFilter(limit, offset int) (int, int) {
	if limit <= 0 {
		limit = 20
	}
	if limit > 200 {
		limit = 200
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

// TestBuildNotificationFilter_DefaultLimit は limit が 0 以下のときデフォルト値になることを確認する
func TestBuildNotificationFilter_DefaultLimit(t *testing.T) {
	limit, offset := buildNotificationFilter(0, 0)
	if limit != 20 {
		t.Errorf("デフォルト limit = %d, want 20", limit)
	}
	if offset != 0 {
		t.Errorf("デフォルト offset = %d, want 0", offset)
	}
}

// TestBuildNotificationFilter_MaxLimit は limit の上限が 200 であることを確認する
func TestBuildNotificationFilter_MaxLimit(t *testing.T) {
	limit, _ := buildNotificationFilter(9999, 0)
	if limit != 200 {
		t.Errorf("最大 limit = %d, want 200", limit)
	}
}

// TestBuildNotificationFilter_NegativeOffset は負の offset がゼロになることを確認する
func TestBuildNotificationFilter_NegativeOffset(t *testing.T) {
	_, offset := buildNotificationFilter(10, -5)
	if offset != 0 {
		t.Errorf("負の offset は 0 になるべき: got %d", offset)
	}
}

// TestBuildNotificationFilter_ValidValues は有効な値がそのまま使用されることを確認する
func TestBuildNotificationFilter_ValidValues(t *testing.T) {
	limit, offset := buildNotificationFilter(50, 100)
	if limit != 50 {
		t.Errorf("limit = %d, want 50", limit)
	}
	if offset != 100 {
		t.Errorf("offset = %d, want 100", offset)
	}
}

// TestNotificationHistoryEntry_SubjectPreserved は Subject フィールドが正確に保持されることを確認する
func TestNotificationHistoryEntry_SubjectPreserved(t *testing.T) {
	subject := "[EDR Alert] Critical: ランサムウェアの疑いあり - endpoint-99"
	e := NotificationHistoryEntry{Subject: subject}
	if e.Subject != subject {
		t.Errorf("Subject = %q, want %q", e.Subject, subject)
	}
	// 日本語が含まれることを確認する
	if !strings.Contains(e.Subject, "ランサムウェア") {
		t.Errorf("Subject に日本語が含まれるべき: %q", e.Subject)
	}
}

// TestNotificationHistoryEntry_ByChannelAggregation はチャンネル別集計ロジックを確認する
func TestNotificationHistoryEntry_ByChannelAggregation(t *testing.T) {
	entries := []*NotificationHistoryEntry{
		{ChannelName: "Slack #soc", Status: "sent"},
		{ChannelName: "Slack #soc", Status: "sent"},
		{ChannelName: "Email: admin@example.com", Status: "failed"},
		{ChannelName: "Slack #soc", Status: "failed"},
		{ChannelName: "Email: admin@example.com", Status: "sent"},
	}

	// チャンネル別に件数を集計する（Stats メソッドのロジックを模倣）
	byChannel := make(map[string]int)
	for _, e := range entries {
		byChannel[e.ChannelName]++
	}

	if byChannel["Slack #soc"] != 3 {
		t.Errorf("Slack チャンネルの件数 = %d, want 3", byChannel["Slack #soc"])
	}
	if byChannel["Email: admin@example.com"] != 2 {
		t.Errorf("Email チャンネルの件数 = %d, want 2", byChannel["Email: admin@example.com"])
	}
}
