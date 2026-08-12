package handlers

import (
	"testing"
)

// ─────────────────────────────────────────────────────────────────────────────
// validateWebhookURL のテスト
// ─────────────────────────────────────────────────────────────────────────────

func TestValidateWebhookURL_ValidHTTPS(t *testing.T) {
	// 有効な HTTPS URL はエラーなく通過する
	validURLs := []string{
		"https://example.com/webhook",
		"https://hooks.slack.com/services/T00/B00/xxx",
		"https://api.pagerduty.com/incidents",
		"https://10.0.0.1:8080/hook",
	}
	for _, u := range validURLs {
		t.Run(u, func(t *testing.T) {
			got := validateWebhookURL(u)
			if got != "" {
				t.Errorf("validateWebhookURL(%q) = %q, want \"\"", u, got)
			}
		})
	}
}

func TestValidateWebhookURL_ValidHTTP(t *testing.T) {
	// 有効な HTTP URL（テスト環境や内部網で使用される）もエラーなく通過する
	validURLs := []string{
		"http://internal.example.com/webhook",
		"http://localhost:9000/hook",
		"http://192.168.1.100/receiver",
	}
	for _, u := range validURLs {
		t.Run(u, func(t *testing.T) {
			got := validateWebhookURL(u)
			if got != "" {
				t.Errorf("validateWebhookURL(%q) = %q, want \"\"", u, got)
			}
		})
	}
}

func TestValidateWebhookURL_Empty(t *testing.T) {
	// 空の URL はエラーを返す
	got := validateWebhookURL("")
	if got == "" {
		t.Error("validateWebhookURL(\"\") = \"\", エラーが期待されました")
	}
}

func TestValidateWebhookURL_InvalidScheme(t *testing.T) {
	// http/https 以外のスキームはエラーを返す
	invalid := []string{
		"ftp://example.com/hook",
		"ws://example.com/hook",
		"example.com/hook",
		"//example.com/hook",
		"javascript:alert(1)",
	}
	for _, u := range invalid {
		t.Run(u, func(t *testing.T) {
			got := validateWebhookURL(u)
			if got == "" {
				t.Errorf("validateWebhookURL(%q): エラーが期待されましたが nil でした", u)
			}
		})
	}
}

func TestValidateWebhookURL_NoHost(t *testing.T) {
	// スキームのみでホスト名がない URL はエラーを返す
	got := validateWebhookURL("https://")
	if got == "" {
		t.Error("validateWebhookURL(\"https://\"): エラーが期待されましたが nil でした")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// validateWebhookEvents のテスト
// ─────────────────────────────────────────────────────────────────────────────

func TestValidateWebhookEvents_ValidEvents(t *testing.T) {
	// 有効なイベントリストはエラーなく通過する
	events := []string{"alert.created", "alert.resolved", "incident.created"}
	got := validateWebhookEvents(&events)
	if got != "" {
		t.Errorf("validateWebhookEvents(有効なイベント) = %q, want \"\"", got)
	}
}

func TestValidateWebhookEvents_EmptyDefaultsToAlertCreated(t *testing.T) {
	// 空のイベントリストはデフォルト ["alert.created"] に補完される
	events := []string{}
	msg := validateWebhookEvents(&events)
	if msg != "" {
		t.Errorf("validateWebhookEvents([]) = %q, want \"\"", msg)
	}
	if len(events) != 1 || events[0] != "alert.created" {
		t.Errorf("デフォルトイベント = %v, want [\"alert.created\"]", events)
	}
}

func TestValidateWebhookEvents_InvalidEvent(t *testing.T) {
	// 無効なイベントタイプを含む場合はエラーを返す
	events := []string{"alert.created", "unknown.event"}
	got := validateWebhookEvents(&events)
	if got == "" {
		t.Error("validateWebhookEvents(無効なイベントを含む): エラーが期待されましたが nil でした")
	}
}

func TestValidateWebhookEvents_AllValidEventTypes(t *testing.T) {
	// すべての定義済みイベントタイプが有効と判定される
	for ev := range validWebhookEvents {
		t.Run(ev, func(t *testing.T) {
			events := []string{ev}
			got := validateWebhookEvents(&events)
			if got != "" {
				t.Errorf("validateWebhookEvents([%q]) = %q, want \"\"", ev, got)
			}
		})
	}
}

func TestValidateWebhookEvents_SingleInvalidEvent(t *testing.T) {
	// リスト内に1つでも無効なイベントがあればエラーを返す
	events := []string{"alert.created", "malformed"}
	got := validateWebhookEvents(&events)
	if got == "" {
		t.Error("validateWebhookEvents: 無効イベントが含まれているのにエラーが返りませんでした")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// validateWebhookPlatform のテスト
// ─────────────────────────────────────────────────────────────────────────────

func TestValidateWebhookPlatform_Valid(t *testing.T) {
	// 有効なプラットフォーム値はエラーなく通過する
	for p := range validWebhookPlatforms {
		t.Run(p, func(t *testing.T) {
			platform := p
			got := validateWebhookPlatform(&platform)
			if got != "" {
				t.Errorf("validateWebhookPlatform(%q) = %q, want \"\"", p, got)
			}
		})
	}
}

func TestValidateWebhookPlatform_EmptyDefaultsToGeneric(t *testing.T) {
	// 空文字列はデフォルト "generic" に補完される
	platform := ""
	msg := validateWebhookPlatform(&platform)
	if msg != "" {
		t.Errorf("validateWebhookPlatform(\"\") = %q, want \"\"", msg)
	}
	if platform != "generic" {
		t.Errorf("デフォルトプラットフォーム = %q, want \"generic\"", platform)
	}
}

func TestValidateWebhookPlatform_Invalid(t *testing.T) {
	// 無効なプラットフォームはエラーを返す
	invalid := []string{"zoom", "jira", "github", "webhook_io"}
	for _, p := range invalid {
		t.Run(p, func(t *testing.T) {
			platform := p
			got := validateWebhookPlatform(&platform)
			if got == "" {
				t.Errorf("validateWebhookPlatform(%q): エラーが期待されましたが nil でした", p)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// validateWebhookRetryCount のテスト
// ─────────────────────────────────────────────────────────────────────────────

func TestValidateWebhookRetryCount_ZeroDefaultsToThree(t *testing.T) {
	// 0 はデフォルト 3 に補完される
	count := 0
	validateWebhookRetryCount(&count)
	if count != 3 {
		t.Errorf("retryCount(0) のデフォルト = %d, want 3", count)
	}
}

func TestValidateWebhookRetryCount_NegativeDefaultsToThree(t *testing.T) {
	// 負の値はデフォルト 3 に補完される
	count := -5
	validateWebhookRetryCount(&count)
	if count != 3 {
		t.Errorf("retryCount(-5) のデフォルト = %d, want 3", count)
	}
}

func TestValidateWebhookRetryCount_PositiveUnchanged(t *testing.T) {
	// 正の値はそのまま保持される
	tests := []int{1, 3, 5, 10}
	for _, c := range tests {
		original := c
		validateWebhookRetryCount(&c)
		if c != original {
			t.Errorf("retryCount(%d) が %d に変更されました", original, c)
		}
	}
}
