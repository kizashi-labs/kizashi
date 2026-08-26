package store

import (
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

// webhook のイベント名は、**送る側が唯一の出どころ**です。
//
// ここには `isValidWebhookEvent` という一覧が置いてありましたが、
// `alert.created` / `alert.resolved` / `incident.closed` / `ioc.matched` /
// `agent.online` を含み、**送られるものとも、画面が出すものとも一致して
// いませんでした** —— 誰とも合わない3つ目の一覧です。
//
// 本物は `internal/notification` の `EmittedWebhookEvents` で、画面の
// 選択肢と揃っていることを `TestTheConsoleOffersOnlyEventsThatAreSent` が
// 確かめます。
//
// **ここで消したのは一覧だけで、検査は増えています。**

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
