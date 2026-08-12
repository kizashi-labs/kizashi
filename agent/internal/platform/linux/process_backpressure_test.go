//go:build linux

package linux

import (
	"context"
	"testing"
	"time"

	"github.com/edr-platform/agent/internal/collector"
)

// TestSendProcEventDelivers verifies a normal send succeeds when the consumer
// has capacity — the common case that must stay lossless.
func TestSendProcEventDelivers(t *testing.T) {
	out := make(chan collector.ProcessEvent, 1)
	if ok := sendProcEvent(context.Background(), out, collector.ProcessEvent{PID: 42}); !ok {
		t.Fatal("sendProcEvent returned false with room in the channel")
	}
	select {
	case got := <-out:
		if got.PID != 42 {
			t.Fatalf("wrong event delivered: PID=%d", got.PID)
		}
	default:
		t.Fatal("event was not delivered to the channel")
	}
}

// TestSendProcEventBackpressureThenCancel is the core of the process-telemetry
// reliability fix: when the consumer is stalled (full/unbuffered) the producer
// must BLOCK (backpressure) rather than silently drop, and unblock only on ctx
// cancel — never losing the event to a `default:` branch.
func TestSendProcEventBackpressureThenCancel(t *testing.T) {
	out := make(chan collector.ProcessEvent) // no buffer, no reader → send blocks
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan bool, 1)
	go func() { done <- sendProcEvent(ctx, out, collector.ProcessEvent{PID: 7}) }()

	// The send must still be blocking (proving it did not drop-and-return).
	select {
	case <-done:
		t.Fatal("sendProcEvent returned before ctx cancel — event was dropped, not backpressured")
	case <-time.After(50 * time.Millisecond):
	}

	cancel()
	select {
	case ok := <-done:
		if ok {
			t.Fatal("sendProcEvent should return false when cancelled while blocked")
		}
	case <-time.After(time.Second):
		t.Fatal("sendProcEvent did not unblock on ctx cancel")
	}
}
