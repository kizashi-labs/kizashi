package graceful

import (
	"context"
	"testing"
)

// mockRunner はテスト用の Runner 実装
type mockRunner struct {
	shutdownCalled bool
	shutdownErr    error
}

func (m *mockRunner) Shutdown(_ context.Context) error {
	m.shutdownCalled = true
	return m.shutdownErr
}

// ─── Runner interface ─────────────────────────────────────────────────────────

func TestRunner_Shutdown_Called(t *testing.T) {
	r := &mockRunner{}
	err := r.Shutdown(context.Background())
	if err != nil {
		t.Fatalf("Shutdown: 予期しないエラー: %v", err)
	}
	if !r.shutdownCalled {
		t.Error("Shutdown: 呼び出されていません")
	}
}

func TestRunner_InterfaceSatisfied(t *testing.T) {
	var r Runner = &mockRunner{}
	_ = r
}
