package collector

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// 空きがあるときは即座に届く。
func TestEmitFile_DeliversWhenRoomAvailable(t *testing.T) {
	out := make(chan FileEvent, 1)
	var dropped atomic.Uint64
	if !EmitFile(context.Background(), out, FileEvent{Path: "/tmp/a"}, &dropped) {
		t.Fatal("空きがあるのに送出できていない")
	}
	if got := (<-out).Path; got != "/tmp/a" {
		t.Fatalf("受信内容が違う: %s", got)
	}
	if dropped.Load() != 0 {
		t.Fatalf("取りこぼしが計上されている: %d", dropped.Load())
	}
}

// 一時的に満杯でも、消費側が追いつけば捨てずに届く。
// 旧実装(default: で即破棄)ではここで失われていた。
func TestEmitFile_WaitsOutTransientBackpressure(t *testing.T) {
	out := make(chan FileEvent, 1)
	out <- FileEvent{Path: "/tmp/occupied"} // 満杯にする
	var dropped atomic.Uint64

	// 少し遅れて消費側が1件引き取る
	go func() {
		time.Sleep(30 * time.Millisecond)
		<-out
	}()

	if !EmitFile(context.Background(), out, FileEvent{Path: "/tmp/burst"}, &dropped) {
		t.Fatal("一時的な詰まりでイベントを捨ててはならない(ランサムバーストが失われる)")
	}
	if dropped.Load() != 0 {
		t.Fatalf("取りこぼしが計上されている: %d", dropped.Load())
	}
}

// 消費側が完全に止まっている場合は、無制限にブロックせず取りこぼしを計上する。
// 数えることが重要 — 旧実装は何も残さず消していた。
func TestEmitFile_CountsDropWhenConsumerWedged(t *testing.T) {
	out := make(chan FileEvent, 1)
	out <- FileEvent{Path: "/tmp/occupied"}
	var dropped atomic.Uint64

	start := time.Now()
	if EmitFile(context.Background(), out, FileEvent{Path: "/tmp/lost"}, &dropped) {
		t.Fatal("消費側が停止しているのに送出成功を返した")
	}
	if elapsed := time.Since(start); elapsed < emitBlockFor {
		t.Fatalf("待たずに諦めている: %v", elapsed)
	}
	if dropped.Load() != 1 {
		t.Fatalf("取りこぼしが計上されていない: %d", dropped.Load())
	}
}

// ctx キャンセルで速やかに抜ける(センサー停止時にハングしない)。
func TestEmitFile_ReturnsOnContextCancel(t *testing.T) {
	out := make(chan FileEvent, 1)
	out <- FileEvent{Path: "/tmp/occupied"}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(20 * time.Millisecond); cancel() }()

	var dropped atomic.Uint64
	if EmitFile(ctx, out, FileEvent{Path: "/tmp/x"}, &dropped) {
		t.Fatal("キャンセル時に送出成功を返した")
	}
}
