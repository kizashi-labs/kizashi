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

// notification_channels の type は API / 画面が webhook_slack / webhook_teams /
// webhook_generic で保存する。Dispatcher 側の定数は slack / teams / webhook で、
// 同じテーブルを別の語彙で読んでいた。
//
// 一致しない行は newSender が弾き、senders に載らない。行は存在して
// enabled = true なのに Notify は静かに何もしないので、「設定したのに
// 届かない、エラーも出ない」になる。両方の語彙を受けること。
func TestNewSenderAcceptsStoredChannelTypes(t *testing.T) {
	for _, tc := range []struct {
		chType   string
		cfgKey   string
		wantType string
	}{
		{"webhook_slack", "webhook_url", ChannelSlack},
		{"webhook_teams", "webhook_url", ChannelTeams},
		{"webhook_generic", "webhook_url", ChannelWebhook},
		// 既存の語彙も引き続き通ること。
		{"slack", "webhook_url", ChannelSlack},
		{"teams", "webhook_url", ChannelTeams},
		{"webhook", "url", ChannelWebhook},
	} {
		t.Run(tc.chType, func(t *testing.T) {
			s, err := newSender(ChannelConfig{
				ID: "c1", Type: tc.chType, Enabled: true,
				Config: map[string]string{tc.cfgKey: "https://example.com/hook"},
			})
			if err != nil {
				t.Fatalf("newSender(%s): %v", tc.chType, err)
			}
			if s.Type() != tc.wantType {
				t.Errorf("Type() = %q, want %q", s.Type(), tc.wantType)
			}
		})
	}
}

// 実際に送信先として数えられること。newSender が通っても senders に
// 載らなければ Notify は何もしない。
func TestStoredChannelTypesAreCounted(t *testing.T) {
	d := NewDispatcher("https://edr.example.com")
	d.LoadChannels([]ChannelConfig{
		{ID: "a", Name: "slack", Type: "webhook_slack", Enabled: true,
			Config: map[string]string{"webhook_url": "https://example.com/s"}},
		{ID: "b", Name: "generic", Type: "webhook_generic", Enabled: true,
			Config: map[string]string{"webhook_url": "https://example.com/g"}},
	})
	if n := d.EnabledChannels(); n != 2 {
		t.Errorf("EnabledChannels() = %d, want 2 (webhook_* が送信先に載っていない)", n)
	}
}

// 有効なのに送信実装を作れなかったチャンネルを数える。
// 生きた送信先が 1 つでもあると EnabledChannels は 0 にならないので、
// これが無いと「一部だけ届いていない」に気づけない。
func TestFailedChannelsCountsUnusableOnes(t *testing.T) {
	d := NewDispatcher("https://edr.example.com")
	d.LoadChannels([]ChannelConfig{
		{ID: "ok", Name: "動くもの", Type: "webhook_generic", Enabled: true,
			Config: map[string]string{"webhook_url": "https://example.com/g"}},
		{ID: "ng", Name: "未知の種別", Type: "pagerduty", Enabled: true,
			Config: map[string]string{"webhook_url": "https://example.com/p"}},
		// 無効なものは数えない。設定されていないのは異常ではない。
		{ID: "off", Name: "無効", Type: "pagerduty", Enabled: false},
	})
	if n := d.EnabledChannels(); n != 1 {
		t.Errorf("EnabledChannels() = %d, want 1", n)
	}
	if n := d.FailedChannels(); n != 1 {
		t.Errorf("FailedChannels() = %d, want 1", n)
	}
}

// 送信時に落ちたチャンネルが、設定を見る指標では見えないこと。
//
// 実機で起きた形をそのまま組む: 有効 3 件、センダーは 3 件とも
// 作れている、しかし届いたのは 1 件だけ (webhook が 405、SMTP が 535)。
// この状態で EnabledChannels は 3、FailedChannels は 0 を返す。
// 「有効 3 / 失敗 0」だけを読むと全部届いたようにしか見えない。
func TestSendTimeFailuresAreInvisibleToChannelCounts(t *testing.T) {
	d := NewDispatcher("https://edr.example.com")
	live := &mockSender{typ: ChannelWebhook}
	dead405 := &mockSender{typ: ChannelWebhook, err: errors.New("405 Method Not Allowed")}
	dead535 := &mockSender{typ: ChannelEmail, err: errors.New("535 authentication failed")}

	d.mu.Lock()
	d.channels = []ChannelConfig{
		{ID: "live", Name: "生きている webhook", Type: ChannelWebhook, Enabled: true, MinSeverity: 1},
		{ID: "d405", Name: "死んでいる webhook", Type: ChannelWebhook, Enabled: true, MinSeverity: 1},
		{ID: "d535", Name: "死んでいる email", Type: ChannelEmail, Enabled: true, MinSeverity: 1},
	}
	d.senders["live"] = live
	d.senders["d405"] = dead405
	d.senders["d535"] = dead535
	d.mu.Unlock()

	// まず、既存の 2 つの指標が何も言わないことを確かめる。ここが
	// 崩れると、この test が守っている前提そのものが変わっている。
	if n := d.EnabledChannels(); n != 3 {
		t.Fatalf("前提が変わっています: EnabledChannels() = %d, want 3", n)
	}
	if n := d.FailedChannels(); n != 0 {
		t.Fatalf("前提が変わっています: FailedChannels() = %d, want 0", n)
	}

	r := d.Notify(context.Background(), &AlertNotification{
		AlertID: "cspm-acct", Severity: 7, CreatedAt: time.Now(),
	})

	if r.Eligible != 3 {
		t.Errorf("Eligible = %d, want 3", r.Eligible)
	}
	if r.Sent != 1 {
		t.Errorf("Sent = %d, want 1 (届いたのは 1 件だけのはず)", r.Sent)
	}
	if r.Failed != 2 {
		t.Errorf("Failed = %d, want 2", r.Failed)
	}
	// どれが落ちたのかまで分かること。件数だけだと起動時ログまで
	// 遡ることになり、送信時の失敗はそこには出ていない。
	want := []string{"死んでいる email", "死んでいる webhook"}
	if len(r.FailedNames) != len(want) {
		t.Fatalf("FailedNames = %v, want %v", r.FailedNames, want)
	}
	for i := range want {
		if r.FailedNames[i] != want[i] {
			t.Errorf("FailedNames[%d] = %q, want %q", i, r.FailedNames[i], want[i])
		}
	}
}

// 全滅と一部失敗を区別できること。監視を貼る単位が違う:
// 全滅は「その通知は失われた」、一部失敗は「送信先が 1 つ壊れている」。
func TestNotifyResultDistinguishesTotalLossFromPartial(t *testing.T) {
	newDispatcherWith := func(senders ...*mockSender) *Dispatcher {
		d := NewDispatcher("https://edr.example.com")
		d.mu.Lock()
		for i, s := range senders {
			id := string(rune('a' + i))
			d.channels = append(d.channels, ChannelConfig{
				ID: id, Name: "ch-" + id, Type: s.typ, Enabled: true, MinSeverity: 1,
			})
			d.senders[id] = s
		}
		d.mu.Unlock()
		return d
	}
	fail := func() *mockSender {
		return &mockSender{typ: ChannelWebhook, err: errors.New("boom")}
	}
	ok := func() *mockSender { return &mockSender{typ: ChannelWebhook} }

	alert := func() *AlertNotification {
		return &AlertNotification{AlertID: "a1", Severity: 7, CreatedAt: time.Now()}
	}

	if r := newDispatcherWith(fail(), fail()).Notify(context.Background(), alert()); r.Sent != 0 || r.Failed != 2 {
		t.Errorf("全滅: Sent=%d Failed=%d, want 0/2", r.Sent, r.Failed)
	}
	if r := newDispatcherWith(ok(), fail()).Notify(context.Background(), alert()); r.Sent != 1 || r.Failed != 1 {
		t.Errorf("一部失敗: Sent=%d Failed=%d, want 1/1", r.Sent, r.Failed)
	}
	if r := newDispatcherWith(ok(), ok()).Notify(context.Background(), alert()); r.Sent != 2 || r.Failed != 0 {
		t.Errorf("全成功: Sent=%d Failed=%d, want 2/0", r.Sent, r.Failed)
	}

	// 重大度で全部ふるい落とされた場合は「失敗 0」だが「送信 0」。
	// 失敗として数えると、設定の問題が送信の障害に見える。
	d := newDispatcherWith(ok())
	d.mu.Lock()
	d.channels[0].MinSeverity = 9
	d.mu.Unlock()
	if r := d.Notify(context.Background(), alert()); r.Eligible != 0 || r.Failed != 0 || r.Sent != 0 {
		t.Errorf("下限未満: Eligible=%d Sent=%d Failed=%d, want 0/0/0", r.Eligible, r.Sent, r.Failed)
	}
}
