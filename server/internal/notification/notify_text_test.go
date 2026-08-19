package notification

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
)

// NotifyText is what a playbook's "notify" action calls, and it used to end
// with an unconditional `return nil`. Notify fans out, logs each failure and
// increments a counter, and returns nothing — so "every channel failed" and
// "there were no channels at all" both arrived at the playbook runner as
// success. The run was recorded as successful and the console showed the
// notification as sent.
//
// The per-send warnings in the log do not correct that. What a SOC loses is not
// the message, it is the belief that on-call was told — and a log line nobody
// is reading does not disturb a belief.

type fakeSender struct {
	calls  atomic.Int32
	err    error
	typeID string
}

func (f *fakeSender) Send(ctx context.Context, n *AlertNotification) error {
	f.calls.Add(1)
	return f.err
}
func (f *fakeSender) Type() string { return f.typeID }

// register wires a sender in as if LoadChannels had built it.
func (d *Dispatcher) register(id string, minSeverity int, s Sender) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.channels = append(d.channels, ChannelConfig{
		ID: id, Name: id, Type: "test", Enabled: true, MinSeverity: minSeverity,
	})
	d.senders[id] = s
}

// The headline.
func TestNotifyTextReportsThatNothingWasSent(t *testing.T) {
	// The two conditions overlap — no channels means nothing was sent — so the
	// assertions have to be on the reason, not merely on "an error came back".
	// Otherwise one guard covers for the other and either could quietly stop
	// applying. They are different problems for the operator: one is "you never
	// configured a destination", the other is "your destination is down".
	t.Run("チャンネルが1つも無い", func(t *testing.T) {
		d := NewDispatcher("http://console.invalid")
		err := d.NotifyText(context.Background(), "ランサムウェア検知", 9)
		if err == nil {
			t.Fatal("送信先が無いのに成功を返しました。" +
				"プレイブックの実行ログには「通知した」と残ります")
		}
		if !strings.Contains(err.Error(), "送信先がありません") {
			t.Errorf("設定漏れが「送信失敗」として報告されています。"+
				"運用担当が直すべき箇所が変わります: %v", err)
		}
	})

	t.Run("全チャンネルが失敗", func(t *testing.T) {
		d := NewDispatcher("http://console.invalid")
		a := &fakeSender{err: errors.New("connection refused"), typeID: "slack"}
		b := &fakeSender{err: errors.New("401"), typeID: "teams"}
		d.register("a", 1, a)
		d.register("b", 1, b)

		err := d.NotifyText(context.Background(), "ランサムウェア検知", 9)
		if err == nil {
			t.Fatal("全チャンネルの送信が失敗したのに成功を返しました")
		}
		if !strings.Contains(err.Error(), "失敗") || !strings.Contains(err.Error(), "2") {
			t.Errorf("送信失敗が件数付きで報告されていません: %v", err)
		}
		if a.calls.Load() != 1 || b.calls.Load() != 1 {
			t.Errorf("送信が試行されていません: a=%d b=%d", a.calls.Load(), b.calls.Load())
		}
	})

	t.Run("重大度が全チャンネルの下限に届かない", func(t *testing.T) {
		d := NewDispatcher("http://console.invalid")
		s := &fakeSender{typeID: "slack"}
		d.register("high-only", 8, s)

		if err := d.NotifyText(context.Background(), "低重大度の通知", 2); err == nil {
			t.Error("重大度の下限で全チャンネルが除外されたのに成功を返しました。" +
				"送信先が無いことと送信できたことは区別されなければなりません")
		}
		if s.calls.Load() != 0 {
			t.Error("下限未満なのに送信されました")
		}
	})
}

// One channel getting through is a success. Otherwise the fix reads as
// "notify always fails", which would flip every working deployment to failed.
func TestNotifyTextSucceedsWhenAnythingGetsThrough(t *testing.T) {
	d := NewDispatcher("http://console.invalid")
	ok := &fakeSender{typeID: "slack"}
	bad := &fakeSender{err: errors.New("timeout"), typeID: "teams"}
	d.register("ok", 1, ok)
	d.register("bad", 1, bad)

	if err := d.NotifyText(context.Background(), "テスト", 9); err != nil {
		t.Errorf("1チャンネルに届いているのに失敗を返しました: %v", err)
	}
	if ok.calls.Load() != 1 {
		t.Error("正常なチャンネルに送信されていません")
	}
	if bad.calls.Load() != 1 {
		t.Error("失敗するチャンネルへの送信が試行されていません")
	}
}

// Notify keeps its fire-and-forget signature — the alert path does not act on
// the result, and changing it would have rippled through every caller — but it
// must still actually send.
func TestNotifyStillFansOut(t *testing.T) {
	d := NewDispatcher("http://console.invalid")
	s := &fakeSender{typeID: "slack"}
	d.register("a", 1, s)

	d.Notify(context.Background(), &AlertNotification{AlertID: "x", Severity: 9})
	if s.calls.Load() != 1 {
		t.Errorf("Notify が送信していません: %d", s.calls.Load())
	}
}

// The counts must be the real ones. A NotifyResult that reported Sent as
// "channels we tried" rather than "channels that succeeded" would make
// NotifyText succeed exactly as unconditionally as before.
func TestTheResultCountsSuccessesNotAttempts(t *testing.T) {
	d := NewDispatcher("http://console.invalid")
	d.register("ok", 1, &fakeSender{typeID: "slack"})
	d.register("bad1", 1, &fakeSender{err: errors.New("x"), typeID: "teams"})
	d.register("bad2", 1, &fakeSender{err: errors.New("y"), typeID: "webhook"})
	d.register("too-high", 9, &fakeSender{typeID: "email"})

	r := d.Notify(context.Background(), &AlertNotification{AlertID: "x", Severity: 5})
	if r.Eligible != 3 {
		t.Errorf("Eligible = %d, want 3 (重大度9のチャンネルは対象外)", r.Eligible)
	}
	if r.Sent != 1 {
		t.Errorf("Sent = %d, want 1 — 試行回数ではなく成功数でなければなりません", r.Sent)
	}
	if r.Failed != 2 {
		t.Errorf("Failed = %d, want 2", r.Failed)
	}
}

// LoadChannels used to overwrite entries in the existing sender map rather than
// replace it. A channel whose config was broken — edited to remove the webhook
// URL, or a row rewritten by hand — was refused by newSender and skipped, which
// left the PREVIOUS sender in place, still pointing at the old destination.
// Notifications kept flowing to a webhook the operator believed they had
// changed, and nothing in the console disagreed.
func TestReloadingDropsTheSenderOfANowBrokenChannel(t *testing.T) {
	d := NewDispatcher("http://console.invalid")

	good := ChannelConfig{ID: "c1", Name: "SOC", Type: ChannelSlack, Enabled: true,
		MinSeverity: 1, Config: map[string]string{"webhook_url": "https://old.example.invalid/x"}}
	d.LoadChannels([]ChannelConfig{good})
	if len(d.senders) != 1 {
		t.Fatalf("前提が崩れています: senders=%d", len(d.senders))
	}

	// Same channel ID, config now unusable.
	broken := good
	broken.Config = map[string]string{}
	d.LoadChannels([]ChannelConfig{broken})

	if _, ok := d.senders["c1"]; ok {
		t.Error("設定が壊れたチャネルの古いセンダーが残っています。" +
			"変更したはずの旧 webhook に送信され続けます")
	}
	if err := d.NotifyText(context.Background(), "テスト", 9); err == nil {
		t.Error("送信先が無いのに成功を返しました")
	}
}

// A channel that is removed outright must go too.
func TestReloadingDropsARemovedChannel(t *testing.T) {
	d := NewDispatcher("http://console.invalid")
	d.LoadChannels([]ChannelConfig{{ID: "c1", Name: "SOC", Type: ChannelSlack, Enabled: true,
		MinSeverity: 1, Config: map[string]string{"webhook_url": "https://x.example.invalid/y"}}})
	d.LoadChannels(nil)

	if len(d.senders) != 0 {
		t.Errorf("削除されたチャネルのセンダーが残っています: %d", len(d.senders))
	}
}
