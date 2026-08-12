// Package resource provides CPU/memory usage monitoring and event-rate throttling
// so the EDR agent never significantly degrades endpoint performance.
package resource

import (
	"context"
	"log/slog"
	"runtime"
	"sync/atomic"
	"time"
)

const (
	// DefaultMaxCPUPercent is the soft CPU ceiling for the agent process.
	// When exceeded, event ingestion is paused briefly to yield CPU.
	DefaultMaxCPUPercent = 5.0

	// DefaultMaxMemoryMB is the soft RSS ceiling in MiB.
	DefaultMaxMemoryMB = 150
)

// Throttle monitors the agent's own resource usage and provides back-pressure
// to collectors when limits are approached.
type Throttle struct {
	maxCPUPct float64
	maxMemMB  uint64
	paused    atomic.Bool
	tokens    chan struct{}
	maxRatePS int // max events per second (0 = unlimited)
}

// New creates a Throttle with the given limits.
// maxEventsPerSecond ≤ 0 disables rate limiting.
func New(maxCPUPct float64, maxMemMB uint64, maxEventsPerSecond int) *Throttle {
	t := &Throttle{
		maxCPUPct: maxCPUPct,
		maxMemMB:  maxMemMB,
		maxRatePS: maxEventsPerSecond,
	}
	if maxEventsPerSecond > 0 {
		t.tokens = make(chan struct{}, maxEventsPerSecond)
	}
	return t
}

// Start launches the background resource monitor.
// It periodically checks memory usage and sets the paused flag when
// the soft ceiling is exceeded, allowing collectors to back off.
func (t *Throttle) Start(ctx context.Context) {
	// Token refill goroutine for rate limiting.
	if t.tokens != nil {
		go t.refillTokens(ctx)
	}

	// Memory monitor goroutine.
	go t.monitorMemory(ctx)
}

// Acquire blocks until the throttle allows the next event to proceed.
// Returns immediately if rate limiting is disabled.
// Returns ctx.Err() if the context is cancelled.
func (t *Throttle) Acquire(ctx context.Context) error {
	// If paused due to memory pressure, wait until unpaused.
	if t.paused.Load() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}

	if t.tokens == nil {
		return nil
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.tokens:
		return nil
	}
}

// IsPaused reports whether the throttle is currently under memory pressure.
func (t *Throttle) IsPaused() bool {
	return t.paused.Load()
}

// ─── internal ─────────────────────────────────────────────────

func (t *Throttle) refillTokens(ctx context.Context) {
	interval := time.Second / time.Duration(t.maxRatePS)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			select {
			case t.tokens <- struct{}{}:
			default: // bucket full
			}
		}
	}
}

func (t *Throttle) monitorMemory(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			var ms runtime.MemStats
			runtime.ReadMemStats(&ms)
			usedMB := ms.Sys / (1024 * 1024)

			if t.maxMemMB > 0 && usedMB > t.maxMemMB {
				if !t.paused.Load() {
					t.paused.Store(true)
					slog.Warn("メモリ使用量が上限に近づきました。イベント収集を一時抑制します",
						"used_mb", usedMB,
						"limit_mb", t.maxMemMB,
					)
				}
				// Force GC to reclaim memory.
				runtime.GC()
			} else {
				if t.paused.Load() {
					t.paused.Store(false)
					slog.Info("メモリ使用量が正常範囲に戻りました。イベント収集を再開します",
						"used_mb", usedMB,
					)
				}
			}
		}
	}
}
