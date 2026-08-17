package scheduler

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/edr-platform/server/internal/detection"
	"github.com/edr-platform/server/internal/metrics"
)

// CurateScheduler grows detection coverage on its own (roadmap P1: "検知コンテンツ
// 自動拡充") while keeping it safe. Each tick it first runs the FP monitor —
// quarantining any curate-enabled synced rule that turned noisy — and then, when
// autoAdvance is on, enables one more bounded, field-supported batch. The order
// matters: clean up noise before adding more, so a bad round is contained before
// the next grows the set. The per-category cap bounds each round's reload, the
// field gate keeps false-green rules off, and the FP monitor is the backstop, so
// the loop is self-regulating: coverage rises until rules start misfiring, then
// the noisy ones fall away.
type CurateScheduler struct {
	svc            *detection.CurateService
	interval       time.Duration
	perCategoryCap int
	fpWindow       time.Duration
	fpThreshold    int
	autoAdvance    bool
	inertEvery     int // run the inert-rule canary once every N ticks (it is a slow signal)
	inertTicks     int
}

// NewCurateScheduler builds the scheduler. When autoAdvance is false the FP monitor
// still runs every tick (so manually/API-enabled rules are protected), but rounds
// are not advanced automatically — operators drive them via the curate API.
func NewCurateScheduler(svc *detection.CurateService, interval time.Duration, perCategoryCap int, fpWindow time.Duration, fpThreshold int, autoAdvance bool) *CurateScheduler {
	// Run the inert-rule canary roughly every 6h regardless of the base interval
	// (it is a slow, once-a-week-grade signal — no need to query every tick).
	inertEvery := 1
	if interval > 0 {
		if e := int((6 * time.Hour) / interval); e > 1 {
			inertEvery = e
		}
	}
	return &CurateScheduler{
		svc:            svc,
		interval:       interval,
		perCategoryCap: perCategoryCap,
		fpWindow:       fpWindow,
		fpThreshold:    fpThreshold,
		autoAdvance:    autoAdvance,
		inertEvery:     inertEvery,
	}
}

// Run ticks until ctx is cancelled. The first tick is delayed by one interval so
// the API server finishes starting before curate touches the rule set.
func (s *CurateScheduler) Run(ctx context.Context) {
	slog.Info("CurateScheduler: 開始",
		"interval", s.interval, "cap", s.perCategoryCap,
		"fp_window", s.fpWindow, "fp_threshold", s.fpThreshold, "auto_advance", s.autoAdvance)

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			trackRun(ctx, "curate_scheduler", s.tick)
		}
	}
}

func (s *CurateScheduler) tick(ctx context.Context) {
	// 0) Self-heal the quarantined⟹disabled invariant: a manual/API enable batch can
	// re-enable an FP-quarantined rule without clearing its state, so it keeps firing.
	if n, err := s.svc.ReconcileQuarantined(ctx); err != nil {
		fail(ctx, err, "CurateScheduler: 隔離整合の是正に失敗")
	} else if n > 0 {
		metrics.CurateQuarantineReconciled.Add(float64(n))
		slog.Warn("CurateScheduler: 隔離済みなのに有効だったルールを再無効化しました", "count", n)
	}

	// 1) Backstop: disable any curate-enabled rule that turned noisy.
	if quarantined, err := s.svc.MonitorFP(ctx, s.fpWindow, s.fpThreshold); err != nil {
		fail(ctx, err, "CurateScheduler: FP監視に失敗")
	} else if len(quarantined) > 0 {
		slog.Info("CurateScheduler: 騒がしいルールを自動隔離しました", "count", len(quarantined))
	}

	// 2) Inert-rule canary: surface curate-enabled rules that never fire (silently
	// inert = broken field references etc.). Grace period 7d so freshly-enabled rules
	// are not flagged; window 7d = "hasn't fired in a week despite being on".
	s.inertTicks++
	if s.inertTicks >= s.inertEvery {
		s.inertTicks = 0
		if inert, err := s.svc.InertRules(ctx, 7*24*time.Hour, 7*24*time.Hour); err != nil {
			fail(ctx, err, "CurateScheduler: 発火0カナリアに失敗")
		} else {
			metrics.CurateInertRules.Set(float64(len(inert)))
			if len(inert) > 0 {
				sample := inert
				if len(sample) > 10 {
					sample = sample[:10]
				}
				slog.Warn("CurateScheduler: 有効化7日超で発火0のルール(サイレントinert疑い)",
					"count", len(inert), "sample", strings.Join(sample, " | "))
			}
		}

		// 2b) False-green canary: the static field-contract check. Unlike the inert
		// canary above (which needs a week of zero alerts), this flags an enabled but
		// field-unsupported rule immediately — a rule enabled outside the curate gate
		// or one whose telemetry coverage regressed. Driven to 0 on 2026-07-03; a rise
		// means the field contract of the enabled set is rotting.
		if fg, err := s.svc.FalseGreenRules(ctx); err != nil {
			fail(ctx, err, "CurateScheduler: false-greenカナリアに失敗")
		} else {
			metrics.CurateFalseGreenRules.Set(float64(len(fg)))
			if len(fg) > 0 {
				sample := fg
				if len(sample) > 10 {
					sample = sample[:10]
				}
				slog.Warn("CurateScheduler: 有効なのにfield非対応のルール(false green=永久にinert)",
					"count", len(fg), "sample", strings.Join(sample, " | "))
			}
		}

		// 2c) Field-gap canary: which missing telemetry field would unlock the most
		// enabled-but-inert rules. The root-cause, ranked complement to 2b — 2b counts
		// how many false-green rules exist; this says which agent field to emit next to
		// resurrect the most of them (emit field X → N rules). A live recall roadmap.
		if inert, gaps, err := s.svc.FieldGapReport(ctx); err != nil {
			fail(ctx, err, "CurateScheduler: field-gapカナリアに失敗")
		} else if len(gaps) > 0 {
			for _, g := range gaps {
				metrics.CurateFieldGap.WithLabelValues(g.Field).Set(float64(g.Rules))
			}
			top := gaps
			if len(top) > 8 {
				top = top[:8]
			}
			parts := make([]string, 0, len(top))
			for _, g := range top {
				parts = append(parts, fmt.Sprintf("%s=%d", g.Field, g.Rules))
			}
			slog.Warn("CurateScheduler: field非対応で有効なのにinertなルール(このフィールドをagentが出せば有効化)",
				"inert_rules", inert, "top_fields", strings.Join(parts, " "))
		}
	}

	// 3) Then advance one bounded round (opt-in).
	if !s.autoAdvance {
		return
	}
	res, err := s.svc.RunRound(ctx, nil, s.perCategoryCap)
	if err != nil {
		fail(ctx, err, "CurateScheduler: curateラウンドに失敗")
		return
	}
	if res.Enabled > 0 {
		slog.Info("CurateScheduler: 同期ルールを段階有効化しました",
			"enabled", res.Enabled, "deferred", res.Deferred, "pending", res.Pending)
	}
}
