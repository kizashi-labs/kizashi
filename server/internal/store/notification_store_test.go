package store

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// ─── 通知チャンネルタイプ検証ヘルパー ─────────────────────────────────────────

// validChannelTypes は許容されるチャンネルタイプの一覧
var validChannelTypes = []string{
	"webhook_slack",
	"webhook_teams",
	"webhook_generic",
	"email",
}

// isValidChannelType はチャンネルタイプが既知の有効な値かどうかを確認する
func isValidChannelType(channelType string) bool {
	for _, t := range validChannelTypes {
		if channelType == t {
			return true
		}
	}
	return false
}

// isWebhookChannelType はチャンネルタイプがWebhook系かどうかを確認する
func isWebhookChannelType(channelType string) bool {
	return strings.HasPrefix(channelType, "webhook_")
}

// isEmailChannelType はチャンネルタイプがemailかどうかを確認する
func isEmailChannelType(channelType string) bool {
	return channelType == "email"
}

// ─── AlertNotifChannel 構造体テスト ──────────────────────────────────────────

// TestAlertNotifChannel_DefaultValues は AlertNotifChannel のゼロ値フィールドを確認する
func TestAlertNotifChannel_DefaultValues(t *testing.T) {
	var c AlertNotifChannel
	if c.ID != "" {
		t.Errorf("ID のデフォルト = %q, want \"\"", c.ID)
	}
	if c.Name != "" {
		t.Errorf("Name のデフォルト = %q, want \"\"", c.Name)
	}
	if c.Type != "" {
		t.Errorf("Type のデフォルト = %q, want \"\"", c.Type)
	}
	if c.Enabled {
		t.Error("Enabled のデフォルトは false であるべき")
	}
}

// TestAlertNotifChannel_FieldAssignment はフィールドへの代入が正しく反映されることを確認する
func TestAlertNotifChannel_FieldAssignment(t *testing.T) {
	now := time.Now()
	cfg := json.RawMessage(`{"url":"https://hooks.slack.com/xxx"}`)
	c := AlertNotifChannel{
		ID:        "ch-001",
		Name:      "Slackアラート",
		Type:      "webhook_slack",
		Config:    cfg,
		Enabled:   true,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if c.ID != "ch-001" {
		t.Errorf("ID = %q, want \"ch-001\"", c.ID)
	}
	if c.Name != "Slackアラート" {
		t.Errorf("Name = %q, want \"Slackアラート\"", c.Name)
	}
	if c.Type != "webhook_slack" {
		t.Errorf("Type = %q, want \"webhook_slack\"", c.Type)
	}
	if !c.Enabled {
		t.Error("Enabled = false, want true")
	}
}

// TestChannelType_ValidTypes は全ての有効なチャンネルタイプが検証に合格することを確認する
func TestChannelType_ValidTypes(t *testing.T) {
	for _, ct := range validChannelTypes {
		if !isValidChannelType(ct) {
			t.Errorf("チャンネルタイプ %q は有効なはずだが検証に失敗した", ct)
		}
	}
}

// TestChannelType_InvalidTypes は無効なチャンネルタイプが検証に失敗することを確認する
func TestChannelType_InvalidTypes(t *testing.T) {
	invalidTypes := []string{"", "sms", "webhook", "Slack", "WEBHOOK_SLACK", "pagerduty", "unknown"}
	for _, ct := range invalidTypes {
		if isValidChannelType(ct) {
			t.Errorf("チャンネルタイプ %q は無効なはずだが検証に合格した", ct)
		}
	}
}

// TestChannelType_WebhookPrefix はwebhook系タイプが正しく識別されることを確認する
func TestChannelType_WebhookPrefix(t *testing.T) {
	webhookTypes := []string{"webhook_slack", "webhook_teams", "webhook_generic"}
	for _, ct := range webhookTypes {
		if !isWebhookChannelType(ct) {
			t.Errorf("チャンネルタイプ %q はwebhook系として識別されるべき", ct)
		}
	}
	// email は webhook ではない
	if isWebhookChannelType("email") {
		t.Error("\"email\" はwebhook系として識別されるべきでない")
	}
}

// TestChannelType_EmailType はemailタイプが正しく識別されることを確認する
func TestChannelType_EmailType(t *testing.T) {
	if !isEmailChannelType("email") {
		t.Error("\"email\" はemail系として識別されるべき")
	}
	// webhook系はemailではない
	for _, ct := range []string{"webhook_slack", "webhook_teams", "webhook_generic"} {
		if isEmailChannelType(ct) {
			t.Errorf("チャンネルタイプ %q はemail系として識別されるべきでない", ct)
		}
	}
}

// TestCreateAlertNotifChannelInput_FieldAssignment は CreateAlertNotifChannelInput のフィールド代入を確認する
func TestCreateAlertNotifChannelInput_FieldAssignment(t *testing.T) {
	cfg := json.RawMessage(`{"url":"https://teams.microsoft.com/webhook/xxx"}`)
	input := CreateAlertNotifChannelInput{
		Name:    "Teamsチャンネル",
		Type:    "webhook_teams",
		Config:  cfg,
		Enabled: true,
	}
	if input.Name != "Teamsチャンネル" {
		t.Errorf("Name = %q, want \"Teamsチャンネル\"", input.Name)
	}
	if input.Type != "webhook_teams" {
		t.Errorf("Type = %q, want \"webhook_teams\"", input.Type)
	}
	if !input.Enabled {
		t.Error("Enabled = false, want true")
	}
}

// TestAlertNotifChannel_ConfigIsRawJSON は Config フィールドが任意の JSON を格納できることを確認する
func TestAlertNotifChannel_ConfigIsRawJSON(t *testing.T) {
	configs := []string{
		`{"url":"https://example.com/hook"}`,
		`{"to":"alert@example.com","subject":"EDRアラート"}`,
		`{}`,
		`{"url":"https://hooks.slack.com/xxx","channel":"#alerts","username":"EDR"}`,
	}
	for _, raw := range configs {
		c := AlertNotifChannel{
			Config: json.RawMessage(raw),
		}
		// JSONとして有効かどうか確認
		var v interface{}
		if err := json.Unmarshal(c.Config, &v); err != nil {
			t.Errorf("Config %q はJSONとして有効であるべき: %v", raw, err)
		}
	}
}

// TestAlertNotifChannel_EnabledDisabledToggle は Enabled フラグの切り替えを確認する
func TestAlertNotifChannel_EnabledDisabledToggle(t *testing.T) {
	c := AlertNotifChannel{Enabled: true}
	if !c.Enabled {
		t.Error("Enabled = false, want true")
	}
	c.Enabled = false
	if c.Enabled {
		t.Error("Enabled = true, want false (無効化後)")
	}
	c.Enabled = true
	if !c.Enabled {
		t.Error("Enabled = false, want true (再有効化後)")
	}
}

// ─── NotificationHistoryEntry 構造体テスト ───────────────────────────────────

// TestNotificationHistoryEntry_DefaultValues は NotificationHistoryEntry のゼロ値を確認する
func TestNotificationHistoryEntry_DefaultValues(t *testing.T) {
	var e NotificationHistoryEntry
	if e.ID != "" {
		t.Errorf("ID のデフォルト = %q, want \"\"", e.ID)
	}
	if e.Status != "" {
		t.Errorf("Status のデフォルト = %q, want \"\"", e.Status)
	}
	if e.ErrorMsg != "" {
		t.Errorf("ErrorMsg のデフォルト = %q, want \"\"", e.ErrorMsg)
	}
}

// TestNotificationHistoryEntry_StatusValues_InStore は有効なstatus値を確認する
func TestNotificationHistoryEntry_StatusValues_InStore(t *testing.T) {
	validStatuses := []string{"sent", "failed"}
	for _, s := range validStatuses {
		e := NotificationHistoryEntry{Status: s}
		if e.Status != s {
			t.Errorf("Status = %q, want %q", e.Status, s)
		}
	}
}

// TestNotificationHistoryEntry_SentStatus は送信成功エントリの構造を確認する
func TestNotificationHistoryEntry_SentStatus(t *testing.T) {
	now := time.Now()
	e := NotificationHistoryEntry{
		ID:          "hist-001",
		ChannelID:   "ch-abc",
		ChannelName: "Slackアラート",
		ChannelType: "webhook_slack",
		Subject:     "重大度9アラート検出",
		Body:        "エージェント agent-xyz でマルウェアが検出されました",
		Status:      "sent",
		SentAt:      now,
	}
	if e.Status != "sent" {
		t.Errorf("Status = %q, want \"sent\"", e.Status)
	}
	if e.ErrorMsg != "" {
		t.Errorf("送信成功エントリは ErrorMsg が空であるべき: got %q", e.ErrorMsg)
	}
}

// TestNotificationHistoryEntry_FailedStatus は送信失敗エントリの構造を確認する
func TestNotificationHistoryEntry_FailedStatus(t *testing.T) {
	now := time.Now()
	e := NotificationHistoryEntry{
		ID:          "hist-002",
		ChannelID:   "ch-def",
		ChannelName: "Teamsアラート",
		ChannelType: "webhook_teams",
		Subject:     "アラート通知",
		Body:        "テスト通知",
		Status:      "failed",
		ErrorMsg:    "接続タイムアウト: context deadline exceeded",
		SentAt:      now,
	}
	if e.Status != "failed" {
		t.Errorf("Status = %q, want \"failed\"", e.Status)
	}
	if e.ErrorMsg == "" {
		t.Error("失敗エントリは ErrorMsg が空でないべき")
	}
}
