// Package transport — runRecvWatchdog (downstream half-open watchdog) unit tests.
// These cover the regression where the server stops *writing* the downstream
// command channel while HTTP/2 + gRPC keepalive stay healthy and conn.GetState()
// stays READY, so stream.Recv() blocks with no EOF and queued isolate/scan
// commands sit undelivered until the OS TCP read timeout fires minutes later.
//
// Arming is gated on the c.serverKeepalive latch (learned out-of-band from the
// unary Heartbeat reply), NOT on receiving a keepalive frame — so a downstream that
// is half-open *from birth* (no frame ever arrives) is still detected.
package transport

import (
	"context"
	"testing"
	"time"
)

// TestRecvWatchdog_HalfOpenFromBirthReconnects is the core regression: the latch is
// set (the server is known to send keepalives, e.g. via a heartbeat) but NOT A
// SINGLE frame ever arrives on the stream. The watchdog must still fire and force a
// reconnect — the case the old "arm only after the first keepalive frame" gate
// missed entirely.
func TestRecvWatchdog_HalfOpenFromBirthReconnects(t *testing.T) {
	c := &GRPCClient{recvTimeout: 40 * time.Millisecond}
	c.serverKeepalive.Store(true) // capability known from a prior heartbeat

	cancelled := make(chan struct{})
	c.mu.Lock()
	c.connected = true
	c.connCancel = func() { close(cancelled) }
	c.mu.Unlock()

	activity := make(chan recvSignal, 1) // never poked → silent from birth
	done := make(chan struct{})
	go func() { c.runRecvWatchdog(context.Background(), activity); close(done) }()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("watchdog did not fire on a downstream half-open from birth")
	}
	select {
	case <-cancelled:
	default:
		t.Fatal("watchdog must call signalDisconnect (connCancel) on silence")
	}
	c.mu.RLock()
	connected := c.connected
	c.mu.RUnlock()
	if connected {
		t.Fatal("connected must be false after the watchdog forces a reconnect")
	}
}

// TestRecvWatchdog_LatchSetMidStream: the stream opens before the heartbeat has
// confirmed capability (latch unset); no frames arrive. Once the latch flips (a
// heartbeat lands), the next deadline must trip a reconnect even though no frame
// was ever received.
func TestRecvWatchdog_LatchSetMidStream(t *testing.T) {
	c := &GRPCClient{recvTimeout: 40 * time.Millisecond}

	cancelled := make(chan struct{})
	c.mu.Lock()
	c.connected = true
	c.connCancel = func() { close(cancelled) }
	c.mu.Unlock()

	activity := make(chan recvSignal, 1)
	done := make(chan struct{})
	go func() { c.runRecvWatchdog(context.Background(), activity); close(done) }()

	// Latch unset for the first ~couple of poll cycles, then a "heartbeat" sets it.
	time.Sleep(90 * time.Millisecond)
	select {
	case <-done:
		t.Fatal("watchdog reconnected while capability was still unknown (would flap on an old server)")
	default:
	}
	c.serverKeepalive.Store(true)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("watchdog did not fire after the latch confirmed keepalive capability")
	}
	select {
	case <-cancelled:
	default:
		t.Fatal("watchdog must signal disconnect once the latch is set and silence persists")
	}
}

// TestRecvWatchdog_OldServerNeverFlaps guards rollout safety: capability is never
// learned (an older server that doesn't send keepalives), and even an occasional
// real command must NOT cause a reconnect, no matter how long the idle gaps.
func TestRecvWatchdog_OldServerNeverFlaps(t *testing.T) {
	c := &GRPCClient{recvTimeout: 25 * time.Millisecond} // latch stays false
	c.mu.Lock()
	c.connected = true
	c.connCancel = func() { t.Error("watchdog must never reconnect against a non-keepalive server") }
	c.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	activity := make(chan recvSignal, 1)
	done := make(chan struct{})
	go func() { c.runRecvWatchdog(ctx, activity); close(done) }()

	// Several idle periods (each >> recvTimeout) with a lone real command in between.
	time.Sleep(70 * time.Millisecond)
	activity <- recvSignal{keepalive: false} // a real command on an old server
	time.Sleep(70 * time.Millisecond)

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("watchdog did not exit on ctx cancellation")
	}
}

// TestRecvWatchdog_KeepaliveFrameArmsAndKeepsAlive: keepalive frames both set the
// latch (here pre-set) and keep resetting the deadline, so a healthy stream never
// trips the watchdog.
func TestRecvWatchdog_KeepaliveFrameArmsAndKeepsAlive(t *testing.T) {
	c := &GRPCClient{recvTimeout: 60 * time.Millisecond}
	c.serverKeepalive.Store(true)
	c.mu.Lock()
	c.connected = true
	c.connCancel = func() { t.Error("watchdog fired despite steady keepalives") }
	c.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	activity := make(chan recvSignal, 1)
	done := make(chan struct{})
	go func() { c.runRecvWatchdog(ctx, activity); close(done) }()

	for i := 0; i < 5; i++ {
		activity <- recvSignal{keepalive: true}
		time.Sleep(20 * time.Millisecond)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("watchdog did not exit on ctx cancellation")
	}
	c.mu.RLock()
	connected := c.connected
	c.mu.RUnlock()
	if !connected {
		t.Fatal("connected must stay true while keepalives keep arriving")
	}
}

// TestRecvWatchdog_CtxCancelExits: on normal stream teardown the connection scope
// is cancelled; the watchdog must return promptly without signalling a disconnect.
func TestRecvWatchdog_CtxCancelExits(t *testing.T) {
	c := &GRPCClient{recvTimeout: time.Hour}
	c.serverKeepalive.Store(true)
	c.mu.Lock()
	c.connCancel = func() { t.Error("watchdog must not signal disconnect on ctx cancel") }
	c.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.runRecvWatchdog(ctx, make(chan recvSignal)); close(done) }()

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("watchdog did not exit promptly on ctx cancellation")
	}
}

// TestRecvWatchdog_ZeroTimeoutUsesDefault guards against a misconfigured client
// (recvTimeout unset) silently disabling the watchdog's timeout.
func TestRecvWatchdog_ZeroTimeoutUsesDefault(t *testing.T) {
	c := &GRPCClient{} // recvTimeout == 0 → must fall back to defaultRecvTimeout
	c.serverKeepalive.Store(true)
	c.mu.Lock()
	c.connCancel = func() {}
	c.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { c.runRecvWatchdog(ctx, make(chan recvSignal)); close(done) }()

	// With the (30s) default it must NOT fire in the next 100ms.
	select {
	case <-done:
		t.Fatal("watchdog fired immediately — zero timeout did not fall back to the default")
	case <-time.After(100 * time.Millisecond):
	}
}
