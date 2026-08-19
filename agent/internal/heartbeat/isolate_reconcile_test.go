package heartbeat

import (
	"context"
	"errors"
	"testing"
	"time"
)

// **巻き戻しが片側しかありませんでした。**
//
// サーバは端末が「まだ隔離中」と言い DB が解除済みのとき
// `should_unisolate` を返します。**逆はありませんでした** —— 隔離
// コマンドが端末に届かなかったとき、DB と画面は「隔離済み」、端末は
// ネットワークに繋がったまま、そして**それを直すものが何もありません**
// でした。
//
// もう1つ、届き方の問題がありました。`FallbackSender` は gRPC を先に
// 試すので、**gRPC が生きている通常時、HTTP の `should_unisolate` は
// 端末に届きません。** 直る条件（gRPC が落ちている）と直らない条件
// （gRPC は生きていて指示だけが落ちた）が入れ替わっていたわけです。
// gRPC 側は応答ヘッダで運ぶようにしました。

type reconcileSender struct {
	resp *HeartbeatResponse
	got  *HeartbeatRequest
}

func (m *reconcileSender) SendHeartbeat(_ context.Context, req *HeartbeatRequest) (*HeartbeatResponse, error) {
	m.got = req
	return m.resp, nil
}

func reporterFor(sender HeartbeatSender, isolated bool, isolate func(string) error, unisolate func() error) *Reporter {
	r := NewReporter("agent-1", "1.0", func() string { return "test" }, "host",
		sender, time.Minute,
		func() bool { return isolated },
		func() int { return 0 },
		unisolate)
	if isolate != nil {
		r.SetIsolateFunc(isolate)
	}
	return r
}

func TestSendOnce_ShouldIsolate_CallsIsolate(t *testing.T) {
	called := 0
	var gotReason string
	r := reporterFor(&reconcileSender{resp: &HeartbeatResponse{ShouldIsolate: true}}, false,
		func(reason string) error { called++; gotReason = reason; return nil }, nil)
	r.sendOnce(context.Background())

	if called != 1 {
		t.Errorf("隔離が %d 回呼ばれました（1 のはずです）。**サーバが"+
			"「隔離されているはず」と言っているのに、端末は繋がったままです**", called)
	}
	if gotReason == "" {
		t.Error("理由が空です。ログに何も残りません")
	}
}

func TestSendOnce_ShouldIsolate_FalseDoesNotCall(t *testing.T) {
	called := 0
	r := reporterFor(&reconcileSender{resp: &HeartbeatResponse{ShouldIsolate: false}}, false,
		func(string) error { called++; return nil }, nil)
	r.sendOnce(context.Background())
	if called != 0 {
		t.Error("**指示されていないのに隔離しました。** 平常時の端末が" +
			"ネットワークから切れます")
	}
}

// **失敗しても次の周回が来ること。** 隔離に失敗したら、次のハートビートで
// もう一度指示が来ます —— そこで止まると、片方向の巻き戻しに戻ります。
func TestSendOnce_ShouldIsolate_FailureDoesNotStopTheReporter(t *testing.T) {
	sender := &reconcileSender{resp: &HeartbeatResponse{ShouldIsolate: true}}
	r := reporterFor(sender, false, func(string) error { return errors.New("iptables に届きません") }, nil)
	r.sendOnce(context.Background())
	r.sendOnce(context.Background())
	if sender.got == nil {
		t.Fatal("2回目のハートビートが送られていません")
	}
}

// **両方向あること。** 片方だけだと、直る失敗と直らない失敗ができます。
func TestBothDirectionsAreWired(t *testing.T) {
	isolated, unisolated := 0, 0
	r := reporterFor(&reconcileSender{resp: &HeartbeatResponse{ShouldIsolate: true}}, false,
		func(string) error { isolated++; return nil },
		func() error { unisolated++; return nil })
	r.sendOnce(context.Background())

	r2 := reporterFor(&reconcileSender{resp: &HeartbeatResponse{ShouldUnisolate: true}}, true,
		func(string) error { isolated++; return nil },
		func() error { unisolated++; return nil })
	r2.sendOnce(context.Background())

	if isolated != 1 || unisolated != 1 {
		t.Errorf("隔離 %d 回・解除 %d 回（それぞれ1回のはずです）。"+
			"**片方向だけだと、直る失敗と直らない失敗ができます**",
			isolated, unisolated)
	}
}

// 隔離する側が `isolate` を差していないとき、黙って落ちないこと。
func TestSendOnce_ShouldIsolate_WithoutAFuncIsNotAPanic(t *testing.T) {
	r := reporterFor(&reconcileSender{resp: &HeartbeatResponse{ShouldIsolate: true}}, false, nil, nil)
	r.sendOnce(context.Background())
}
