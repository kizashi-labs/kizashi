package ingestion

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc/credentials/insecure"
)

// TestListenAndServe_ReturnsOnContextCancel is a regression test for graceful
// shutdown: before, ListenAndServe(addr) had no context and blocked forever, so
// on SIGTERM the process was SIGKILLed mid-stream and dropped received-but-
// unpersisted events. Now ListenAndServe(ctx, addr) must return promptly when the
// context is cancelled (GracefulStop, with a forced Stop backstop).
func TestListenAndServe_ReturnsOnContextCancel(t *testing.T) {
	s := &Server{
		shutdown: make(chan struct{}),
		tlsCreds: insecure.NewCredentials(),
	}
	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() { errCh <- s.ListenAndServe(ctx, "127.0.0.1:0") }()

	// Give Serve a moment to bind and start (no active streams to drain).
	time.Sleep(200 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("グレースフル停止でエラーを返した: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("context cancel 後5秒以内に ListenAndServe が返らない — グレースフル停止が未結線")
	}
}
