package scheduler

import (
	"context"
	"log/slog"
	"time"

	"github.com/edr-platform/server/internal/store"
	edrsync "github.com/edr-platform/server/internal/sync"
)

// RuleChangePublisher fires a rules.invalidate signal so the detection engine and
// the API Sigma pipeline reload the rule set immediately after a sync (the same
// subject the manual rule-edit path publishes).
type RuleChangePublisher interface {
	Publish(subject string, data []byte) error
}

// sigmaSyncer is the slice of *edrsync.SigmaHQSyncer the scheduler depends on,
// extracted as an interface so runOnce's reload-only-on-change logic is unit-
// testable with a fake (no network/DB).
type sigmaSyncer interface {
	IsRunning() bool
	Sync(ctx context.Context, autoEnable bool, paths []string) error
	Status() *edrsync.SyncStatus
}

// SigmaSyncScheduler periodically syncs SigmaHQ community rules into the rule
// store — the Sigma analog of YARASyncScheduler. It closes the gap that the
// SigmaHQ syncer was manual-trigger only: detection content now grows on its own.
//
// Quality is bounded by the existing syncer: DefaultSyncPaths scopes the import to
// categories that map to our telemetry (process_creation/registry/network/dns/…),
// and parseSigmaYAML only enables stable/test rules — so coverage grows without
// flooding the engine with unevaluatable rules. After each sync it publishes
// rules.invalidate for live reload.
type SigmaSyncScheduler struct {
	syncer    sigmaSyncer
	publisher RuleChangePublisher
	interval  time.Duration
}

// NewSigmaSyncScheduler creates a scheduler that syncs SigmaHQ rules periodically.
// pub may be nil (no live-reload signal; rules still apply on the next poll/restart).
func NewSigmaSyncScheduler(ruleStore *store.RuleStore, githubToken string, pub RuleChangePublisher, interval time.Duration) *SigmaSyncScheduler {
	return &SigmaSyncScheduler{
		syncer:    edrsync.NewSigmaHQSyncer(ruleStore, githubToken),
		publisher: pub,
		interval:  interval,
	}
}

// Run syncs once at startup, then on each interval tick, until ctx is cancelled.
func (s *SigmaSyncScheduler) Run(ctx context.Context) {
	slog.Info("SigmaSyncScheduler: 開始", "interval", s.interval)

	trackRun(ctx, "sigma_sync_scheduler", s.runOnce)

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			trackRun(ctx, "sigma_sync_scheduler", s.runOnce)
		}
	}
}

func (s *SigmaSyncScheduler) runOnce(ctx context.Context) {
	if s.syncer.IsRunning() {
		slog.Info("SigmaSyncScheduler: 前回の同期が実行中のためスキップします")
		return
	}
	slog.Info("SigmaSyncScheduler: SigmaHQルール同期を開始します")
	// autoEnable=false → synced rules are IMPORTED but left DISABLED for curated
	// opt-in. Auto-enabling the full SigmaHQ corpus (~2000 stable/test rules in the
	// supported categories) floods a real host: noisy community rules (e.g.
	// "Publicly Accessible RDP Service") fire on benign activity, and the
	// rules.invalidate reload of 2000+ rules spikes the DB connection pool (observed
	// 2026-06-25 — "too many clients"). Operators enable curated subsets via the
	// rules API. nil paths → DefaultSyncPaths (telemetry-mapped categories only).
	if err := s.syncer.Sync(ctx, false, nil); err != nil {
		fail(ctx, err, "SigmaSyncScheduler: 同期に失敗しました")
		return
	}
	st := s.syncer.Status()
	if st == nil {
		return
	}
	slog.Info("SigmaSyncScheduler: 同期完了",
		"imported", st.Imported, "updated", st.Updated,
		"skipped", st.Skipped, "failed", st.Failed)

	// Reload the live rule set only when something actually changed.
	if s.publisher != nil && (st.Imported > 0 || st.Updated > 0) {
		if err := s.publisher.Publish("rules.invalidate", []byte("{}")); err != nil {
			fail(ctx, err, "SigmaSyncScheduler: rules.invalidate発行失敗")
		} else {
			slog.Info("SigmaSyncScheduler: rules.invalidate を発行しました（検知エンジン再読込）")
		}
	}
}
