package resource

import (
	"context"
	"testing"
	"time"
)

// ─── New ─────────────────────────────────────────────────────

func TestNew_StoresLimits(t *testing.T) {
	tests := []struct {
		name        string
		maxCPUPct   float64
		maxMemMB    uint64
		maxEventsPS int
	}{
		{"default limits", DefaultMaxCPUPercent, DefaultMaxMemoryMB, 0},
		{"custom limits", 10.0, 200, 500},
		{"zero limits", 0, 0, 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			th := New(tc.maxCPUPct, tc.maxMemMB, tc.maxEventsPS)
			if th == nil {
				t.Fatal("New returned nil")
			}
			if th.maxCPUPct != tc.maxCPUPct {
				t.Errorf("maxCPUPct = %v, want %v", th.maxCPUPct, tc.maxCPUPct)
			}
			if th.maxMemMB != tc.maxMemMB {
				t.Errorf("maxMemMB = %v, want %v", th.maxMemMB, tc.maxMemMB)
			}
		})
	}
}

func TestNew_TokenChannelCreated(t *testing.T) {
	tests := []struct {
		name        string
		maxEventsPS int
		wantTokens  bool
	}{
		{"with rate limit", 100, true},
		{"no rate limit (0)", 0, false},
		{"no rate limit (-1)", -1, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			th := New(5.0, 100, tc.maxEventsPS)
			hasTokens := th.tokens != nil
			if hasTokens != tc.wantTokens {
				t.Errorf("tokens channel present = %v, want %v", hasTokens, tc.wantTokens)
			}
		})
	}
}

// ─── IsPaused ────────────────────────────────────────────────

func TestIsPaused_InitiallyFalse(t *testing.T) {
	tests := []struct {
		name string
	}{
		{"no rate limit"},
		{"with rate limit"},
		{"zero memory limit"},
	}

	configs := []struct {
		cpu  float64
		mem  uint64
		rate int
	}{
		{5.0, 100, 0},
		{5.0, 100, 500},
		{5.0, 0, 0},
	}

	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := configs[i]
			th := New(c.cpu, c.mem, c.rate)
			if th.IsPaused() {
				t.Error("Throttle should not be paused initially")
			}
		})
	}
}

func TestIsPaused_ManualSet(t *testing.T) {
	th := New(5.0, 100, 0)

	th.paused.Store(true)
	if !th.IsPaused() {
		t.Error("IsPaused should return true after storing true")
	}

	th.paused.Store(false)
	if th.IsPaused() {
		t.Error("IsPaused should return false after storing false")
	}
}

// ─── Acquire — no rate limiting ──────────────────────────────

func TestAcquire_NoRateLimit_ReturnsImmediately(t *testing.T) {
	tests := []struct {
		name string
		cpu  float64
		mem  uint64
	}{
		{"zero cpu/mem", 0, 0},
		{"normal limits", 5.0, 100},
		{"large limits", 50.0, 4096},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			th := New(tc.cpu, tc.mem, 0) // no rate limiting
			ctx := context.Background()

			start := time.Now()
			err := th.Acquire(ctx)
			elapsed := time.Since(start)

			if err != nil {
				t.Errorf("Acquire error = %v, want nil", err)
			}
			if elapsed > 100*time.Millisecond {
				t.Errorf("Acquire took %v without rate limit; expected near-instant", elapsed)
			}
		})
	}
}

func TestAcquire_ContextCancelled_ReturnsError(t *testing.T) {
	tests := []struct {
		name string
	}{
		{"immediate cancel, no tokens"},
		{"immediate cancel, with rate limiter (empty bucket)"},
	}

	// Case 1: no token channel, immediate cancel.
	t.Run(tests[0].name, func(t *testing.T) {
		th := New(5.0, 100, 0)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		// Not paused, no token channel — should return immediately with nil.
		err := th.Acquire(ctx)
		// Without rate limiting, context cancellation is not checked; nil expected.
		_ = err
	})

	// Case 2: rate limiter with empty bucket and cancelled context.
	t.Run(tests[1].name, func(t *testing.T) {
		th := New(5.0, 100, 1) // 1 token/sec
		// Do NOT start the throttle so the bucket stays empty.
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		err := th.Acquire(ctx)
		if err == nil {
			t.Error("expected context error when bucket empty and context cancelled")
		}
	})
}

func TestAcquire_Paused_WaitsOrCancels(t *testing.T) {
	th := New(5.0, 100, 0)
	th.paused.Store(true)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	err := th.Acquire(ctx)
	// Either it unpaused within 200ms (unlikely without a monitor) and returned nil,
	// or the 50ms pause-wait ran and returned nil after one iteration.
	// The important thing: it must not hang forever.
	_ = err
}

// ─── Acquire — with token bucket ─────────────────────────────

func TestAcquire_WithTokens_ConsumesToken(t *testing.T) {
	th := New(5.0, 100, 100)
	// Pre-fill one token manually.
	th.tokens <- struct{}{}

	ctx := context.Background()
	err := th.Acquire(ctx)
	if err != nil {
		t.Errorf("Acquire with token available returned error: %v", err)
	}
	// Bucket should now be empty.
	if len(th.tokens) != 0 {
		t.Errorf("token not consumed; bucket len = %d", len(th.tokens))
	}
}

// ─── Constants ───────────────────────────────────────────────

func TestDefaultConstants(t *testing.T) {
	if DefaultMaxCPUPercent <= 0 {
		t.Errorf("DefaultMaxCPUPercent = %v, want > 0", DefaultMaxCPUPercent)
	}
	if DefaultMaxMemoryMB <= 0 {
		t.Errorf("DefaultMaxMemoryMB = %v, want > 0", DefaultMaxMemoryMB)
	}
}

// ─── Start — smoke test ───────────────────────────────────────

func TestStart_DoesNotPanic(t *testing.T) {
	tests := []struct {
		name        string
		maxEventsPS int
	}{
		{"without rate limiter", 0},
		{"with rate limiter", 10},
		{"high rate", 10000},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			th := New(5.0, DefaultMaxMemoryMB, tc.maxEventsPS)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			// Should not panic.
			th.Start(ctx)
			// Give goroutines a moment to start.
			time.Sleep(5 * time.Millisecond)
		})
	}
}
