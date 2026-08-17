package transport

import (
	"context"
	"testing"

	v1 "github.com/edr-platform/proto/agent/v1"
)

// エージェントは実行結果を一度も返していなかった。AckSender インターフェースも
// 再送処理も実装済みだったが、NewExecutor に nil が渡され、SendAck を実装した型が
// agent 内に 1 つも存在しなかった（"ack sender set below" の "below" が無かった）。
// 器が両端に揃っていて間だけが繋がっていない、という壊れ方だったので、
// 繋がっていることをテストで固定する。

func TestSendAckQueuesResult(t *testing.T) {
	c := &GRPCClient{}

	if err := c.SendAck(context.Background(), "row-1", true, "", nil); err != nil {
		t.Fatalf("SendAck: %v", err)
	}
	if err := c.SendAck(context.Background(), "row-2", false, "isolate failed", nil); err != nil {
		t.Fatalf("SendAck: %v", err)
	}

	acks := c.drainAcks()
	if len(acks) != 2 {
		t.Fatalf("積まれた ACK = %d 件, want 2", len(acks))
	}
	if acks[0].GetCommandId() != "row-1" || acks[0].GetStatus() != v1.CommandAck_ACK_STATUS_SUCCESS {
		t.Errorf("1 件目 = %v", acks[0])
	}
	if acks[1].GetStatus() != v1.CommandAck_ACK_STATUS_FAILED {
		t.Errorf("失敗が SUCCESS として積まれています: %v", acks[1])
	}
	if acks[1].GetError() != "isolate failed" {
		t.Errorf("エラー文字列が落ちています: %q", acks[1].GetError())
	}

	// drain 後は空。同じ結果を二度送るとサーバ側で二重更新になる。
	if rest := c.drainAcks(); rest != nil {
		t.Errorf("drain 後に %d 件残っています", len(rest))
	}
}

// id の無い ACK はサーバ側で対応付けられない。積むと、対応付け不能な記録が
// 増えるだけで害しかない。
func TestSendAckDropsEmptyCommandID(t *testing.T) {
	c := &GRPCClient{}
	if err := c.SendAck(context.Background(), "", true, "", nil); err != nil {
		t.Fatalf("SendAck: %v", err)
	}
	if acks := c.drainAcks(); acks != nil {
		t.Errorf("id の無い ACK が %d 件積まれています", len(acks))
	}
}

// 送信に失敗した結果を捨てると、サーバ側は期限切れとして畳む。つまり実際には
// 成功した隔離が timeout として記録される。積み直しは順序も保つ必要がある
// （後から積まれた結果が先に届くと、古い結果で上書きされ得る）。
func TestRequeueAcksKeepsOrder(t *testing.T) {
	c := &GRPCClient{}
	_ = c.SendAck(context.Background(), "later", true, "", nil)

	c.requeueAcks([]*v1.CommandAck{{CommandId: "earlier"}})

	acks := c.drainAcks()
	if len(acks) != 2 {
		t.Fatalf("ACK = %d 件, want 2", len(acks))
	}
	if acks[0].GetCommandId() != "earlier" {
		t.Errorf("積み直した ACK が先頭にありません: %q", acks[0].GetCommandId())
	}
	if acks[1].GetCommandId() != "later" {
		t.Errorf("2 件目 = %q, want \"later\"", acks[1].GetCommandId())
	}
}

// SendEvents は「オフライン経路も含めた唯一の出口」なので、ここで相乗りさせる。
// batch が既に acks を持っている場合（バッファから再生された batch）は
// 上書きしない — 再生時に別の結果で置き換えると、記録が食い違う。
func TestSendEventsAttachesPendingAcks(t *testing.T) {
	buf, err := NewRingBuffer(t.TempDir(), 1)
	if err != nil {
		t.Fatalf("NewRingBuffer: %v", err)
	}
	c := &GRPCClient{buffer: buf}
	_ = c.SendAck(context.Background(), "row-1", true, "", nil)

	batch := &v1.EventBatch{AgentId: "agent-1"}
	// 未接続なのでバッファ経路に落ちるが、相乗りの付与はその前に行われる。
	// バッファに載る batch にも ACK が入るので、復帰後の再生でも結果は届く。
	_ = c.SendEvents(context.Background(), batch)

	if len(batch.GetAcks()) != 1 {
		t.Fatalf("batch に載った ACK = %d 件, want 1", len(batch.GetAcks()))
	}
	if batch.GetAcks()[0].GetCommandId() != "row-1" {
		t.Errorf("載った ACK = %q", batch.GetAcks()[0].GetCommandId())
	}
}
