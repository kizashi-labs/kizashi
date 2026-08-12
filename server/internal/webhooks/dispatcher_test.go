package webhooks

import (
	"context"
	"strings"
	"testing"
	"time"
)

// ─── NewDispatcher ────────────────────────────────────────────────────────────

func TestNewDispatcher_NotNil(t *testing.T) {
	d := NewDispatcher(nil)
	if d == nil {
		t.Fatal("NewDispatcher は nil を返すべきではありません")
	}
}

func TestNewDispatcher_HasHTTPClient(t *testing.T) {
	d := NewDispatcher(nil)
	if d.httpClient == nil {
		t.Error("httpClient が nil です")
	}
}

// ─── AddConfig ────────────────────────────────────────────────────────────────

func TestAddConfig_EmptyURL_ReturnsError(t *testing.T) {
	d := NewDispatcher(nil)
	err := d.AddConfig(&WebhookConfig{Name: "No URL"})
	if err == nil {
		t.Error("URL 未設定は エラーを返すべきです")
	}
}

func TestAddConfig_DefaultsRetryCountTo3(t *testing.T) {
	d := NewDispatcher(nil)
	cfg := &WebhookConfig{URL: "https://example.com/hook", RetryCount: 0}
	_ = d.AddConfig(cfg)
	if cfg.RetryCount != 3 {
		t.Errorf("AddConfig: デフォルト RetryCount got %d, want 3", cfg.RetryCount)
	}
}

func TestAddConfig_DefaultsPlatformToGeneric(t *testing.T) {
	d := NewDispatcher(nil)
	cfg := &WebhookConfig{URL: "https://example.com/hook"}
	_ = d.AddConfig(cfg)
	if cfg.Platform != "generic" {
		t.Errorf("AddConfig: デフォルト Platform got %q, want generic", cfg.Platform)
	}
}

func TestAddConfig_PreservesExplicitPlatform(t *testing.T) {
	d := NewDispatcher(nil)
	cfg := &WebhookConfig{URL: "https://example.com/hook", Platform: "slack"}
	_ = d.AddConfig(cfg)
	if cfg.Platform != "slack" {
		t.Errorf("AddConfig: Platform got %q, want slack", cfg.Platform)
	}
}

func TestAddConfig_PreservesExplicitRetryCount(t *testing.T) {
	d := NewDispatcher(nil)
	cfg := &WebhookConfig{URL: "https://example.com/hook", RetryCount: 5}
	_ = d.AddConfig(cfg)
	if cfg.RetryCount != 5 {
		t.Errorf("AddConfig: RetryCount got %d, want 5", cfg.RetryCount)
	}
}

func TestAddConfig_AddsToConfigs(t *testing.T) {
	d := NewDispatcher(nil)
	_ = d.AddConfig(&WebhookConfig{URL: "https://example.com/a"})
	_ = d.AddConfig(&WebhookConfig{URL: "https://example.com/b"})
	stats := d.GetStats()
	if stats.TotalConfigs != 2 {
		t.Errorf("AddConfig: TotalConfigs got %d, want 2", stats.TotalConfigs)
	}
}

// ─── LoadConfigs ──────────────────────────────────────────────────────────────

func TestLoadConfigs_ReplacesExisting(t *testing.T) {
	d := NewDispatcher(nil)
	_ = d.AddConfig(&WebhookConfig{URL: "https://old.example.com"})

	newCfgs := []*WebhookConfig{
		{URL: "https://new1.example.com", Enabled: true},
		{URL: "https://new2.example.com", Enabled: true},
	}
	d.LoadConfigs(newCfgs)

	stats := d.GetStats()
	if stats.TotalConfigs != 2 {
		t.Errorf("LoadConfigs: TotalConfigs got %d, want 2", stats.TotalConfigs)
	}
}

func TestLoadConfigs_EmptySlice_ClearsAll(t *testing.T) {
	d := NewDispatcher(nil)
	_ = d.AddConfig(&WebhookConfig{URL: "https://example.com"})
	d.LoadConfigs([]*WebhookConfig{})
	stats := d.GetStats()
	if stats.TotalConfigs != 0 {
		t.Errorf("LoadConfigs(空): TotalConfigs got %d, want 0", stats.TotalConfigs)
	}
}

// ─── GetStats ─────────────────────────────────────────────────────────────────

func TestGetStats_EmptyDispatcher(t *testing.T) {
	d := NewDispatcher(nil)
	stats := d.GetStats()
	if stats.TotalConfigs != 0 || stats.EnabledConfigs != 0 {
		t.Errorf("空の Dispatcher: TotalConfigs=%d, EnabledConfigs=%d", stats.TotalConfigs, stats.EnabledConfigs)
	}
}

func TestGetStats_CountsEnabledConfigs(t *testing.T) {
	d := NewDispatcher(nil)
	d.LoadConfigs([]*WebhookConfig{
		{URL: "https://a.example.com", Enabled: true},
		{URL: "https://b.example.com", Enabled: false},
		{URL: "https://c.example.com", Enabled: true},
	})
	stats := d.GetStats()
	if stats.TotalConfigs != 3 {
		t.Errorf("TotalConfigs: got %d, want 3", stats.TotalConfigs)
	}
	if stats.EnabledConfigs != 2 {
		t.Errorf("EnabledConfigs: got %d, want 2", stats.EnabledConfigs)
	}
}

func TestGetStats_SumsDeliveries(t *testing.T) {
	d := NewDispatcher(nil)
	d.LoadConfigs([]*WebhookConfig{
		{URL: "https://a.example.com", DeliveryCount: 10, FailureCount: 2},
		{URL: "https://b.example.com", DeliveryCount: 5, FailureCount: 1},
	})
	stats := d.GetStats()
	if stats.TotalDeliveries != 15 {
		t.Errorf("TotalDeliveries: got %d, want 15", stats.TotalDeliveries)
	}
	if stats.TotalFailures != 3 {
		t.Errorf("TotalFailures: got %d, want 3", stats.TotalFailures)
	}
}

// ─── Dispatch ─────────────────────────────────────────────────────────────────

func TestDispatch_NoMatchingConfigs_ReturnsZero(t *testing.T) {
	d := NewDispatcher(nil)
	d.LoadConfigs([]*WebhookConfig{
		{URL: "https://a.example.com", Enabled: true, Events: []string{"alert.resolved"}},
	})
	count := d.Dispatch(context.Background(), "alert.created", nil)
	if count != 0 {
		t.Errorf("不一致イベント: got %d, want 0", count)
	}
}

func TestDispatch_DisabledConfigs_Skipped(t *testing.T) {
	d := NewDispatcher(nil)
	d.LoadConfigs([]*WebhookConfig{
		{URL: "https://a.example.com", Enabled: false, Events: []string{"*"}},
	})
	count := d.Dispatch(context.Background(), "alert.created", nil)
	if count != 0 {
		t.Errorf("無効 config はスキップされるべきです: got %d, want 0", count)
	}
}

func TestDispatch_MatchingConfig_ReturnsCount(t *testing.T) {
	d := NewDispatcher(nil)
	d.LoadConfigs([]*WebhookConfig{
		{URL: "https://a.example.com", Enabled: true, Events: []string{"alert.created"}},
		{URL: "https://b.example.com", Enabled: true, Events: []string{"alert.created"}},
	})
	count := d.Dispatch(context.Background(), "alert.created", nil)
	if count != 2 {
		t.Errorf("Dispatch: got %d matched, want 2", count)
	}
}

func TestDispatch_WildcardStar_MatchesAll(t *testing.T) {
	d := NewDispatcher(nil)
	d.LoadConfigs([]*WebhookConfig{
		{URL: "https://a.example.com", Enabled: true, Events: []string{"*"}},
	})
	count := d.Dispatch(context.Background(), "any.event.type", nil)
	if count != 1 {
		t.Errorf("ワイルドカード(*): got %d, want 1", count)
	}
}

func TestDispatch_WildcardAll_MatchesAll(t *testing.T) {
	d := NewDispatcher(nil)
	d.LoadConfigs([]*WebhookConfig{
		{URL: "https://a.example.com", Enabled: true, Events: []string{"all"}},
	})
	count := d.Dispatch(context.Background(), "incident.created", nil)
	if count != 1 {
		t.Errorf("ワイルドカード(all): got %d, want 1", count)
	}
}

// ─── signPayload ──────────────────────────────────────────────────────────────

func TestSignPayload_EmptySecret_ReturnsEmpty(t *testing.T) {
	d := NewDispatcher(nil)
	sig := d.signPayload("", []byte("body"))
	if sig != "" {
		t.Errorf("空シークレット: got %q, want empty", sig)
	}
}

func TestSignPayload_DeterministicForSameInput(t *testing.T) {
	d := NewDispatcher(nil)
	body := []byte(`{"event":"alert.created"}`)
	sig1 := d.signPayload("my-secret", body)
	sig2 := d.signPayload("my-secret", body)
	if sig1 != sig2 {
		t.Error("signPayload: 同一入力で同一シグネチャが返るべきです")
	}
}

func TestSignPayload_DiffersForDifferentInput(t *testing.T) {
	d := NewDispatcher(nil)
	sig1 := d.signPayload("secret", []byte("body-a"))
	sig2 := d.signPayload("secret", []byte("body-b"))
	if sig1 == sig2 {
		t.Error("signPayload: 異なる入力で異なるシグネチャが返るべきです")
	}
}

func TestSignPayload_DiffersForDifferentSecret(t *testing.T) {
	d := NewDispatcher(nil)
	body := []byte("same body")
	sig1 := d.signPayload("secret-a", body)
	sig2 := d.signPayload("secret-b", body)
	if sig1 == sig2 {
		t.Error("signPayload: 異なるシークレットで異なるシグネチャが返るべきです")
	}
}

func TestSignPayload_ReturnsHexString(t *testing.T) {
	d := NewDispatcher(nil)
	sig := d.signPayload("secret", []byte("body"))
	// HMAC-SHA256 は 32 バイト = hex で 64 文字
	if len(sig) != 64 {
		t.Errorf("signPayload: hex 長 got %d, want 64", len(sig))
	}
}

// ─── formatSlack ──────────────────────────────────────────────────────────────

func TestFormatSlack_HasBlocksKey(t *testing.T) {
	d := NewDispatcher(nil)
	p := &WebhookPayload{Event: "alert.created", Timestamp: time.Now(), Source: "edr-platform"}
	result := d.formatSlack(p)
	if _, ok := result["blocks"]; !ok {
		t.Error("formatSlack: 'blocks' キーが含まれているべきです")
	}
}

func TestFormatSlack_ContainsEventInText(t *testing.T) {
	d := NewDispatcher(nil)
	p := &WebhookPayload{Event: "alert.created", Timestamp: time.Now(), Source: "edr-platform"}
	result := d.formatSlack(p)
	// blocks[0].text.text に event 名が含まれる
	blocks, ok := result["blocks"].([]map[string]interface{})
	if !ok || len(blocks) == 0 {
		t.Fatal("formatSlack: blocks が空です")
	}
	textBlock := blocks[0]
	inner, ok := textBlock["text"].(map[string]interface{})
	if !ok {
		t.Fatal("formatSlack: text ブロックが期待通りの構造ではありません")
	}
	text, _ := inner["text"].(string)
	if !strings.Contains(text, "alert.created") {
		t.Errorf("formatSlack: text にイベント名が含まれていません: %s", text)
	}
}

// ─── formatTeams ──────────────────────────────────────────────────────────────

func TestFormatTeams_HasMessageCardType(t *testing.T) {
	d := NewDispatcher(nil)
	p := &WebhookPayload{Event: "incident.created", Timestamp: time.Now(), Source: "edr-platform"}
	result := d.formatTeams(p)
	if result["@type"] != "MessageCard" {
		t.Errorf("formatTeams: @type got %q, want MessageCard", result["@type"])
	}
}

func TestFormatTeams_ContainsSummaryWithEvent(t *testing.T) {
	d := NewDispatcher(nil)
	p := &WebhookPayload{Event: "agent.offline", Timestamp: time.Now(), Source: "edr-platform"}
	result := d.formatTeams(p)
	summary, _ := result["summary"].(string)
	if !strings.Contains(summary, "agent.offline") {
		t.Errorf("formatTeams: summary %q にイベント名が含まれていません", summary)
	}
}

// ─── formatPagerDuty ──────────────────────────────────────────────────────────

func TestFormatPagerDuty_EventActionIsTrigger(t *testing.T) {
	d := NewDispatcher(nil)
	p := &WebhookPayload{Event: "alert.created", Timestamp: time.Now(), Data: map[string]interface{}{}}
	result := d.formatPagerDuty(p)
	if result["event_action"] != "trigger" {
		t.Errorf("formatPagerDuty: event_action got %q, want trigger", result["event_action"])
	}
}

func TestFormatPagerDuty_DefaultSeverityInfo(t *testing.T) {
	d := NewDispatcher(nil)
	p := &WebhookPayload{Event: "alert.created", Timestamp: time.Now(), Data: map[string]interface{}{}}
	result := d.formatPagerDuty(p)
	payload := result["payload"].(map[string]interface{})
	if payload["severity"] != "info" {
		t.Errorf("formatPagerDuty: デフォルト severity got %q, want info", payload["severity"])
	}
}

func TestFormatPagerDuty_CriticalSeverityMapping(t *testing.T) {
	d := NewDispatcher(nil)
	p := &WebhookPayload{
		Event:     "alert.created",
		Timestamp: time.Now(),
		Data:      map[string]interface{}{"severity": "critical"},
	}
	result := d.formatPagerDuty(p)
	payload := result["payload"].(map[string]interface{})
	if payload["severity"] != "critical" {
		t.Errorf("formatPagerDuty critical: severity got %q, want critical", payload["severity"])
	}
}

func TestFormatPagerDuty_MediumSeverityMapping(t *testing.T) {
	d := NewDispatcher(nil)
	p := &WebhookPayload{
		Event:     "alert.created",
		Timestamp: time.Now(),
		Data:      map[string]interface{}{"severity": "medium"},
	}
	result := d.formatPagerDuty(p)
	payload := result["payload"].(map[string]interface{})
	if payload["severity"] != "warning" {
		t.Errorf("formatPagerDuty medium→warning: severity got %q, want warning", payload["severity"])
	}
}

// ─── matchesEvent ─────────────────────────────────────────────────────────────

func TestMatchesEvent_ExactMatch(t *testing.T) {
	if !matchesEvent([]string{"alert.created", "incident.created"}, "alert.created") {
		t.Error("matchesEvent: 完全一致 は true を返すべきです")
	}
}

func TestMatchesEvent_WildcardStar(t *testing.T) {
	if !matchesEvent([]string{"*"}, "any.event") {
		t.Error("matchesEvent: ワイルドカード(*) は true を返すべきです")
	}
}

func TestMatchesEvent_WildcardAll(t *testing.T) {
	if !matchesEvent([]string{"all"}, "any.event") {
		t.Error("matchesEvent: ワイルドカード(all) は true を返すべきです")
	}
}

func TestMatchesEvent_NoMatch(t *testing.T) {
	if matchesEvent([]string{"alert.resolved"}, "alert.created") {
		t.Error("matchesEvent: 不一致 は false を返すべきです")
	}
}

func TestMatchesEvent_EmptySubscribedList_ReturnsFalse(t *testing.T) {
	if matchesEvent([]string{}, "alert.created") {
		t.Error("matchesEvent: 空リストは false を返すべきです")
	}
}
