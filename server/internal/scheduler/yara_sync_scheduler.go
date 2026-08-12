package scheduler

import (
	"context"
	"log/slog"
	"time"

	"github.com/edr-platform/server/internal/store"
	edrsync "github.com/edr-platform/server/internal/sync"
)

// YARASyncScheduler runs YARA community rule sync on a configurable interval.
type YARASyncScheduler struct {
	syncer   *edrsync.YARAHQSyncer
	interval time.Duration
}

// NewYARASyncScheduler creates a scheduler that syncs YARA rules periodically.
// interval is how often to sync (e.g. 7*24*time.Hour for weekly).
func NewYARASyncScheduler(yaraStore *store.YARAStore, githubToken string, interval time.Duration) *YARASyncScheduler {
	return &YARASyncScheduler{
		syncer:   edrsync.NewYARAHQSyncer(yaraStore, githubToken),
		interval: interval,
	}
}

// Run starts the scheduler loop. It syncs once at startup, then on each interval tick.
func (s *YARASyncScheduler) Run(ctx context.Context) {
	slog.Info("YARASyncScheduler: 開始", "interval", s.interval)

	s.runOnce(ctx)

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runOnce(ctx)
		}
	}
}

func (s *YARASyncScheduler) runOnce(ctx context.Context) {
	if s.syncer.IsRunning() {
		slog.Info("YARASyncScheduler: 前回の同期が実行中のためスキップします")
		return
	}
	slog.Info("YARASyncScheduler: YARA コミュニティルール同期を開始します")
	if err := s.syncer.Sync(ctx, false, nil); err != nil {
		slog.Error("YARASyncScheduler: 同期に失敗しました", "error", err)
		return
	}
	st := s.syncer.Status()
	if st != nil {
		slog.Info("YARASyncScheduler: 同期完了",
			"imported", st.Imported,
			"updated", st.Updated,
			"failed", st.Failed,
		)
	}
}
