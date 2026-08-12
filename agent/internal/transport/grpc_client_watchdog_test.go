// Package transport — sendWithWatchdog (half-open stream watchdog) unit tests.
// These cover the regression where stream.Send() blocks forever on an
// application-level half-open stream (server stopped reading, HTTP/2 + keepalive
// healthy), wedging the live-send and drain paths while the unary heartbeat keeps
// the agent "online" and detection silently dies.
package transport

import (
	"errors"
	"testing"
	"time"
)

// TestSendWithWatchdog_Success: a send that returns promptly passes its result
// through and does NOT trip the disconnect.
func TestSendWithWatchdog_Success(t *testing.T) {
	c := &GRPCClient{sendTimeout: time.Second}
	c.mu.Lock()
	c.connected = true
	c.mu.Unlock()

	if err := c.sendWithWatchdog(func() error { return nil }); err != nil {
		t.Fatalf("expected nil error on successful send, got %v", err)
	}
	c.mu.RLock()
	connected := c.connected
	c.mu.RUnlock()
	if !connected {
		t.Fatal("connected must stay true after a successful send")
	}
}

// TestSendWithWatchdog_SendErrorPassesThrough: a real Send error is returned
// verbatim (the caller, SendEvents/drainBuffer, decides whether to reconnect).
func TestSendWithWatchdog_SendErrorPassesThrough(t *testing.T) {
	c := &GRPCClient{sendTimeout: time.Second}
	c.mu.Lock()
	c.connected = true
	c.mu.Unlock()

	want := errors.New("stream closed")
	if err := c.sendWithWatchdog(func() error { return want }); !errors.Is(err, want) {
		t.Fatalf("expected the send error to pass through, got %v", err)
	}
}

// TestSendWithWatchdog_TimeoutForcesReconnect is the core regression: a send that
// blocks (half-open stream) must trip the watchdog, force a disconnect, and return
// an error so the batch falls back to the buffer instead of being silently lost.
func TestSendWithWatchdog_TimeoutForcesReconnect(t *testing.T) {
	c := &GRPCClient{sendTimeout: 50 * time.Millisecond}

	// signalDisconnect cancels the connection scope; in production that cancels the
	// stream ctx and unblocks the wedged Send. Model that here: the blocked send
	// returns only once connCancel has fired.
	cancelled := make(chan struct{})
	c.mu.Lock()
	c.connected = true
	c.connCancel = func() { close(cancelled) }
	c.mu.Unlock()

	start := time.Now()
	err := c.sendWithWatchdog(func() error {
		<-cancelled // mimics Send unblocking when its stream ctx is cancelled
		return errors.New("context canceled")
	})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected a timeout error from the watchdog, got nil")
	}
	if elapsed < 50*time.Millisecond {
		t.Fatalf("watchdog returned too early (%s); should wait for the timeout", elapsed)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("watchdog did not join the send goroutine promptly (%s)", elapsed)
	}
	c.mu.RLock()
	connected := c.connected
	c.mu.RUnlock()
	if connected {
		t.Fatal("connected must be false after the watchdog forces a reconnect")
	}
}

// TestSendWithWatchdog_ZeroTimeoutUsesDefault guards against a misconfigured client
// (sendTimeout unset) silently disabling the watchdog.
func TestSendWithWatchdog_ZeroTimeoutUsesDefault(t *testing.T) {
	c := &GRPCClient{} // sendTimeout == 0 → must fall back to defaultSendTimeout
	c.mu.Lock()
	c.connected = true
	c.mu.Unlock()

	// A fast success still works regardless of the (large) default timeout.
	if err := c.sendWithWatchdog(func() error { return nil }); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}
