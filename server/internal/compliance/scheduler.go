package compliance

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Scheduler runs periodic compliance evaluations against all enrolled agents.
type Scheduler struct {
	evaluator *Evaluator
}

// NewScheduler creates a new Scheduler backed by the given database pool.
func NewScheduler(db *pgxpool.Pool) *Scheduler {
	return &Scheduler{
		evaluator: NewEvaluator(db),
	}
}

// Start launches the background goroutine that runs evaluations daily at 02:00 UTC.
// It returns immediately; the scheduler stops when ctx is cancelled.
func (s *Scheduler) Start(ctx context.Context) {
	go s.run(ctx)
}

// run is the main scheduler loop. It sleeps until 02:00 UTC, then evaluates
// all agents against every configured framework.
func (s *Scheduler) run(ctx context.Context) {
	slog.Info("compliance scheduler: started")
	for {
		next := nextRunTime()
		slog.Info("compliance scheduler: next evaluation", "at", next.Format(time.RFC3339))

		select {
		case <-ctx.Done():
			slog.Info("compliance scheduler: stopped")
			return
		case <-time.After(time.Until(next)):
			s.runEvaluation(ctx)
		}
	}
}

// runEvaluation evaluates all agents against all configured frameworks.
func (s *Scheduler) runEvaluation(parentCtx context.Context) {
	ctx, cancel := context.WithTimeout(parentCtx, 2*time.Hour)
	defer cancel()

	frameworks := []Framework{FrameworkCIS, FrameworkNIST, FrameworkSOC2}
	for _, fw := range frameworks {
		slog.Info("compliance scheduler: evaluating framework", "framework", fw)
		reports, err := s.evaluator.EvaluateAll(ctx, fw)
		if err != nil {
			slog.Error("compliance scheduler: evaluation error",
				"framework", fw, "error", err)
			continue
		}
		slog.Info("compliance scheduler: framework evaluation complete",
			"framework", fw, "agents_evaluated", len(reports))
	}
}

// nextRunTime returns the next 02:00 UTC wall-clock time.
// If it is already past 02:00 today, the returned time is 02:00 tomorrow.
func nextRunTime() time.Time {
	now := time.Now().UTC()
	next := time.Date(now.Year(), now.Month(), now.Day(), 2, 0, 0, 0, time.UTC)
	if !next.After(now) {
		next = next.Add(24 * time.Hour)
	}
	return next
}
