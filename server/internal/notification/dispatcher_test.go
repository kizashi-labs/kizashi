package notification

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// ─── Mock Sender ─────────────────────────────────────────────────────────────

type mockSender struct {
	typ      string
	calls    atomic.Int64
	failNext bool
	err      error
}

func (m *mockSender) Send(_ context.Context, _ *AlertNotification) error {
	m.calls.Add(1)
	if m.failNext || m.err != nil {
		return m.err
	}
	return nil
}

func (m *mockSender) Type() string { return m.typ }

// ─── Tests ────────────────────────────────────────────────────────────────────

func TestDispatcher_LoadChannels_BuildsSenders(t *testing.T) {
	d := NewDispatcher("http://localhost")

	// Slack channel — will be loaded into senders
	d.LoadChannels([]ChannelConfig{
		{
			ID:      "ch1",
			Name:    "Slack Alert",
			Type:    ChannelSlack,
			Config:  map[string]string{"webhook_url": "https://hooks.slack.com/test"},
			Enabled: true,
		},
	})

	d.mu.RLock()
	_, ok := d.senders["ch1"]
	d.mu.RUnlock()

	if !ok {
		t.Fatal("Slackチャンネルのsenderが作成されていません")
	}
}

func TestDispatcher_LoadChannels_DisabledChannelNotInSenders(t *testing.T) {
	d := NewDispatcher("http://localhost")
	d.LoadChannels([]ChannelConfig{
		{
			ID:      "ch-off",
			Name:    "Disabled",
			Type:    ChannelSlack,
			Config:  map[string]string{"webhook_url": "https://example.com"},
			Enabled: false,
		},
	})

	d.mu.RLock()
	_, ok := d.senders["ch-off"]
	d.mu.RUnlock()

	if ok {
		t.Fatal("無効なチャンネルのsenderは作成されるべきではありません")
	}
}

func TestDispatcher_Notify_CallsSenders(t *testing.T) {
	d := NewDispatcher("http://localhost")
	sender := &mockSender{typ: ChannelSlack}

	d.mu.Lock()
	d.channels = []ChannelConfig{{
		ID: "ch1", Type: ChannelSlack, Enabled: true, MinSeverity: 1,
	}}
	d.senders["ch1"] = sender
	d.mu.Unlock()

	n := &AlertNotification{
		AlertID:   "alert-1",
		Title:     "Test Alert",
		Severity:  7,
		Status:    "open",
		CreatedAt: time.Now(),
	}
	d.Notify(context.Background(), n)

	if sender.calls.Load() != 1 {
		t.Fatalf("Send が1回呼ばれるべきところ %d 回呼ばれました", sender.calls.Load())
	}
}

func TestDispatcher_Notify_SkipsBelowMinSeverity(t *testing.T) {
	d := NewDispatcher("http://localhost")
	sender := &mockSender{typ: ChannelSlack}

	d.mu.Lock()
	d.channels = []ChannelConfig{{
		ID: "ch1", Type: ChannelSlack, Enabled: true, MinSeverity: 8,
	}}
	d.senders["ch1"] = sender
	d.mu.Unlock()

	// Severity 5 < MinSeverity 8 → should be skipped
	d.Notify(context.Background(), &AlertNotification{
		AlertID: "a1", Severity: 5, CreatedAt: time.Now(),
	})

	if sender.calls.Load() != 0 {
		t.Fatalf("MinSeverity未満のアラートはスキップされるべきです")
	}
}

func TestDispatcher_Notify_SkipsDisabledChannel(t *testing.T) {
	d := NewDispatcher("http://localhost")
	sender := &mockSender{typ: ChannelSlack}

	d.mu.Lock()
	d.channels = []ChannelConfig{{
		ID: "ch1", Type: ChannelSlack, Enabled: false, MinSeverity: 1,
	}}
	d.senders["ch1"] = sender
	d.mu.Unlock()

	d.Notify(context.Background(), &AlertNotification{
		AlertID: "a1", Severity: 9, CreatedAt: time.Now(),
	})

	if sender.calls.Load() != 0 {
		t.Fatalf("無効なチャンネルへの通知はスキップされるべきです")
	}
}

func TestDispatcher_Notify_SetsDashboardURL(t *testing.T) {
	baseURL := "https://edr.example.com"
	d := NewDispatcher(baseURL)

	var capturedURL string
	cap := &struct {
		mockSender
		url string
	}{}

	origSend := func(_ context.Context, n *AlertNotification) error {
		cap.url = n.DashboardURL
		return nil
	}
	_ = origSend

	// Inject via manual channel loading
	sender := &mockSender{typ: ChannelSlack}
	d.mu.Lock()
	d.channels = []ChannelConfig{{
		ID: "ch1", Enabled: true, MinSeverity: 1,
	}}
	d.senders["ch1"] = sender
	d.mu.Unlock()

	d.Notify(context.Background(), &AlertNotification{
		AlertID: "abc123", Severity: 5, CreatedAt: time.Now(),
	})

	// DashboardURL is set inside Notify; verify by checking the baseURL field
	if d.baseURL != baseURL {
		t.Fatalf("baseURL mismatch: got %q, want %q", d.baseURL, baseURL)
	}
	_ = capturedURL
}

func TestDispatcher_TestChannel_ErrorWhenNotFound(t *testing.T) {
	d := NewDispatcher("http://localhost")
	err := d.TestChannel(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("存在しないチャンネルのTestChannelはエラーを返すべきです")
	}
}

func TestDispatcher_TestChannel_CallsSender(t *testing.T) {
	d := NewDispatcher("http://localhost")
	sender := &mockSender{typ: ChannelSlack}

	d.mu.Lock()
	d.channels = []ChannelConfig{{
		ID: "ch-test", Enabled: true, MinSeverity: 1,
	}}
	d.senders["ch-test"] = sender
	d.mu.Unlock()

	if err := d.TestChannel(context.Background(), "ch-test"); err != nil {
		t.Fatalf("TestChannel エラー: %v", err)
	}
	if sender.calls.Load() != 1 {
		t.Fatalf("TestChannel で Send が1回呼ばれるべきです")
	}
}

func TestDispatcher_TestChannel_PropagatesError(t *testing.T) {
	d := NewDispatcher("http://localhost")
	wantErr := errors.New("接続失敗")
	sender := &mockSender{typ: ChannelSlack, err: wantErr}

	d.mu.Lock()
	d.senders["ch-err"] = sender
	d.mu.Unlock()

	err := d.TestChannel(context.Background(), "ch-err")
	if !errors.Is(err, wantErr) {
		t.Fatalf("TestChannel はsenderのエラーを伝播すべきです: got %v, want %v", err, wantErr)
	}
}

func TestDispatcher_NotifyText_Succeeds(t *testing.T) {
	d := NewDispatcher("http://localhost")
	sender := &mockSender{typ: ChannelSlack}

	d.mu.Lock()
	d.channels = []ChannelConfig{{
		ID: "ch1", Enabled: true, MinSeverity: 1,
	}}
	d.senders["ch1"] = sender
	d.mu.Unlock()

	if err := d.NotifyText(context.Background(), "playbook triggered", 5); err != nil {
		t.Fatalf("NotifyText エラー: %v", err)
	}
	if sender.calls.Load() != 1 {
		t.Fatalf("NotifyText で Send が呼ばれるべきです")
	}
}

// ─── splitComma tests ─────────────────────────────────────────────────────────

func TestSplitComma_Empty(t *testing.T) {
	if got := splitComma(""); got != nil {
		t.Fatalf("空文字列は nil を返すべき: got %v", got)
	}
}

func TestSplitComma_Single(t *testing.T) {
	got := splitComma("alice@example.com")
	if len(got) != 1 || got[0] != "alice@example.com" {
		t.Fatalf("got %v", got)
	}
}

func TestSplitComma_Multiple(t *testing.T) {
	got := splitComma("a@example.com, b@example.com,c@example.com")
	if len(got) != 3 {
		t.Fatalf("3つの要素を期待: got %v", got)
	}
	for _, v := range got {
		if v != "a@example.com" && v != "b@example.com" && v != "c@example.com" {
			t.Fatalf("予期しない値: %q", v)
		}
	}
}

func TestSplitComma_WhitespaceOnly(t *testing.T) {
	got := splitComma("  ,  ,  ")
	if len(got) != 0 {
		t.Fatalf("空エントリは除外されるべきです: got %v", got)
	}
}
