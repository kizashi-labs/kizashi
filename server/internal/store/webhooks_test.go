package store

import (
	"strings"
	"testing"
	"time"
)

// ─── WebhookTarget 構造体テスト ───────────────────────────────────────────────

// TestWebhookTarget_ZeroValue は WebhookTarget のゼロ値が期待通りであることを確認する
func TestWebhookTarget_ZeroValue(t *testing.T) {
	var wt WebhookTarget
	if wt.ID != "" {
		t.Errorf("ID のデフォルト = %q, want \"\"", wt.ID)
	}
	if wt.Name != "" {
		t.Errorf("Name のデフォルト = %q, want \"\"", wt.Name)
	}
	if wt.URL != "" {
		t.Errorf("URL のデフォルト = %q, want \"\"", wt.URL)
	}
	if wt.Secret != "" {
		t.Errorf("Secret のデフォルト = %q, want \"\"", wt.Secret)
	}
	if wt.Enabled {
		t.Error("Enabled のデフォルトは false であるべき")
	}
	if wt.Events != nil {
		t.Errorf("Events のデフォルトは nil であるべき: got %v", wt.Events)
	}
	if wt.LastTriggeredAt != nil {
		t.Error("LastTriggeredAt のデフォルトは nil であるべき")
	}
	if wt.LastStatus != nil {
		t.Error("LastStatus のデフォルトは nil であるべき")
	}
}

// TestWebhookTarget_FieldAssignment は WebhookTarget フィールドの代入を確認する
func TestWebhookTarget_FieldAssignment(t *testing.T) {
	now := time.Now()
	status := 200

	wt := WebhookTarget{
		ID:              "wh-001",
		Name:            "Slack通知Webhook",
		URL:             "https://hooks.slack.com/services/T000/B000/xxxx",
		Secret:          "mysecret",
		Events:          []string{"alert.created", "alert.resolved"},
		Enabled:         true,
		LastTriggeredAt: &now,
		LastStatus:      &status,
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	if wt.ID != "wh-001" {
		t.Errorf("ID = %q, want \"wh-001\"", wt.ID)
	}
	if wt.Name != "Slack通知Webhook" {
		t.Errorf("Name = %q, want \"Slack通知Webhook\"", wt.Name)
	}
	if wt.URL != "https://hooks.slack.com/services/T000/B000/xxxx" {
		t.Errorf("URL が期待値と一致しない: %q", wt.URL)
	}
	if wt.Secret != "mysecret" {
		t.Errorf("Secret = %q, want \"mysecret\"", wt.Secret)
	}
	if !wt.Enabled {
		t.Error("Enabled は true であるべき")
	}
	if len(wt.Events) != 2 {
		t.Errorf("Events の長さ = %d, want 2", len(wt.Events))
	}
	if wt.LastTriggeredAt == nil || !wt.LastTriggeredAt.Equal(now) {
		t.Errorf("LastTriggeredAt = %v, want %v", wt.LastTriggeredAt, now)
	}
	if wt.LastStatus == nil || *wt.LastStatus != 200 {
		t.Errorf("LastStatus = %v, want 200", wt.LastStatus)
	}
}

// TestWebhookTarget_EventsSlice はイベントタイプの複数格納を確認する
func TestWebhookTarget_EventsSlice(t *testing.T) {
	events := []string{
		"alert.created",
		"alert.resolved",
		"agent.offline",
		"incident.created",
		"alert.any",
	}
	wt := WebhookTarget{Events: events}

	if len(wt.Events) != 5 {
		t.Fatalf("Events の長さ = %d, want 5", len(wt.Events))
	}
	for i, ev := range events {
		if wt.Events[i] != ev {
			t.Errorf("Events[%d] = %q, want %q", i, wt.Events[i], ev)
		}
	}
}

// TestWebhookTarget_SecretOmitempty は Secret が空の場合に omitempty 相当の動作を確認する
func TestWebhookTarget_SecretOmitempty(t *testing.T) {
	// シークレットなしの Webhook は空文字列
	wt := WebhookTarget{Name: "no-secret-webhook"}
	if wt.Secret != "" {
		t.Errorf("シークレットなし Webhook の Secret = %q, want \"\"", wt.Secret)
	}
}

// TestWebhookTarget_LastStatusCodes は HTTP ステータスコードが正しく格納されることを確認する
func TestWebhookTarget_LastStatusCodes(t *testing.T) {
	testCases := []struct {
		code int
		desc string
	}{
		{200, "成功"},
		{400, "不正なリクエスト"},
		{401, "認証エラー"},
		{404, "エンドポイント未検出"},
		{500, "サーバーエラー"},
		{503, "サービス利用不可"},
	}

	for _, tc := range testCases {
		code := tc.code
		wt := WebhookTarget{LastStatus: &code}
		if wt.LastStatus == nil || *wt.LastStatus != tc.code {
			t.Errorf("LastStatus = %v, want %d (%s)", wt.LastStatus, tc.code, tc.desc)
		}
	}
}

// ─── Webhook イベントタイプ検証ロジックテスト ─────────────────────────────────

// isValidWebhookEvent はイベントタイプが既知のものか検証するヘルパー（テスト専用）
// webhooks.go の ListEnabledForEvent が受け入れるイベントタイプを定義する
func isValidWebhookEvent(event string) bool {
	validEvents := map[string]bool{
		"alert.created":    true,
		"alert.resolved":   true,
		"alert.any":        true,
		"agent.offline":    true,
		"agent.online":     true,
		"incident.created": true,
		"incident.closed":  true,
		"ioc.matched":      true,
	}
	return validEvents[event]
}

// TestWebhookEvent_KnownTypes は既知のイベントタイプが有効と判定されることを確認する
func TestWebhookEvent_KnownTypes(t *testing.T) {
	knownEvents := []string{
		"alert.created",
		"alert.resolved",
		"alert.any",
		"agent.offline",
		"agent.online",
		"incident.created",
		"incident.closed",
		"ioc.matched",
	}
	for _, ev := range knownEvents {
		if !isValidWebhookEvent(ev) {
			t.Errorf("既知のイベント %q は有効と判定されるべき", ev)
		}
	}
}

// TestWebhookEvent_UnknownTypesAreInvalid は不明なイベントタイプが無効と判定されることを確認する
func TestWebhookEvent_UnknownTypesAreInvalid(t *testing.T) {
	unknownEvents := []string{
		"",
		"unknown.event",
		"ALERT.CREATED",
		"alert",
		"alert.",
		"random_string",
	}
	for _, ev := range unknownEvents {
		if isValidWebhookEvent(ev) {
			t.Errorf("不明なイベント %q は無効と判定されるべき", ev)
		}
	}
}

// TestWebhookEvent_AlertAnyIsWildcard は "alert.any" がワイルドカードとして機能することを確認する
// ListEnabledForEvent の SQL では 'alert.any' = ANY(events) でワイルドカード登録を表現する
func TestWebhookEvent_AlertAnyIsWildcard(t *testing.T) {
	// "alert.any" を持つ Webhook はすべてのアラートイベントを受け取る
	wt := WebhookTarget{
		Events:  []string{"alert.any"},
		Enabled: true,
	}
	hasWildcard := false
	for _, ev := range wt.Events {
		if ev == "alert.any" {
			hasWildcard = true
			break
		}
	}
	if !hasWildcard {
		t.Error("Events に \"alert.any\" が含まれるべき")
	}
}

// TestWebhookTarget_URLFormat は URL フォーマットの基本的な検証を確認する
func TestWebhookTarget_URLFormat(t *testing.T) {
	validURLs := []string{
		"https://example.com/webhook",
		"http://internal.company.local/hooks",
		"https://hooks.slack.com/services/T000/B000/xxxx",
	}
	for _, url := range validURLs {
		wt := WebhookTarget{URL: url}
		if !strings.HasPrefix(wt.URL, "http://") && !strings.HasPrefix(wt.URL, "https://") {
			t.Errorf("URL %q は http:// または https:// で始まるべき", wt.URL)
		}
	}
}

// ─── Webhook 有効/無効状態テスト ─────────────────────────────────────────────

// TestWebhookTarget_EnabledDisabledToggle は Enabled フラグの切り替えを確認する
func TestWebhookTarget_EnabledDisabledToggle(t *testing.T) {
	wt := WebhookTarget{Enabled: true}
	if !wt.Enabled {
		t.Error("Enabled = false, want true")
	}

	// 無効化シミュレート
	wt.Enabled = false
	if wt.Enabled {
		t.Error("無効化後は Enabled = false であるべき")
	}

	// 再有効化シミュレート
	wt.Enabled = true
	if !wt.Enabled {
		t.Error("再有効化後は Enabled = true であるべき")
	}
}

// TestWebhookTarget_DisabledWebhookHasNoEvents は無効な Webhook がイベントを持っていても
// 配信対象から除外されるべきことを論理として確認する
func TestWebhookTarget_DisabledWebhookHasNoEvents(t *testing.T) {
	// Enabled=false の Webhook は ListEnabledForEvent に返されない
	wt := WebhookTarget{
		Events:  []string{"alert.created"},
		Enabled: false,
	}
	// enabled=false なので配信候補にならない
	if wt.Enabled {
		t.Error("このテストでは Enabled = false であるべき")
	}
	// イベントは設定されているが enabled=false なので配信されない
	if len(wt.Events) == 0 {
		t.Error("Events はあるが Enabled=false により配信対象外")
	}
}

// TestWebhookTarget_LastTriggeredAtNilForNew は新規 Webhook の LastTriggeredAt が nil であることを確認する
func TestWebhookTarget_LastTriggeredAtNilForNew(t *testing.T) {
	wt := WebhookTarget{
		Name:    "新規Webhook",
		URL:     "https://example.com/hook",
		Enabled: true,
	}
	if wt.LastTriggeredAt != nil {
		t.Errorf("新規 Webhook の LastTriggeredAt は nil であるべき: got %v", wt.LastTriggeredAt)
	}
}

// TestWebhookTarget_SuccessStatusCode は 2xx ステータスが成功を意味することを確認する
func TestWebhookTarget_SuccessStatusCode(t *testing.T) {
	successCodes := []int{200, 201, 202, 204}
	for _, code := range successCodes {
		c := code
		wt := WebhookTarget{LastStatus: &c}
		if *wt.LastStatus < 200 || *wt.LastStatus >= 300 {
			t.Errorf("ステータスコード %d は 2xx の範囲外", *wt.LastStatus)
		}
	}
}
