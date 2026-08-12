package scheduler

import (
	"context"
	"log/slog"
	"time"

	"github.com/edr-platform/server/internal/behavioral"
	"github.com/edr-platform/server/internal/store"
	"github.com/jackc/pgx/v5/pgxpool"
)

// BaselineRebuilder は6時間ごとに全エージェントのベースラインを再構築する。
type BaselineRebuilder struct {
	pool   *pgxpool.Pool
	engine *behavioral.Engine
	bStore *store.BehavioralBaselineStore
}

// NewBaselineRebuilder creates a new BaselineRebuilder.
func NewBaselineRebuilder(pool *pgxpool.Pool, engine *behavioral.Engine) *BaselineRebuilder {
	return &BaselineRebuilder{
		pool:   pool,
		engine: engine,
		bStore: store.NewBehavioralBaselineStore(pool),
	}
}

// Run は起動時に1回実行し、以後6時間ごとに再構築する。
func (r *BaselineRebuilder) Run(ctx context.Context) {
	// テーブルが存在しない場合は何もしない
	if !r.tableExists(ctx) {
		slog.Warn("agent_behavioral_baselines テーブルが存在しません、スキップします")
		return
	}

	// 起動直後は少し待ってから初回実行（DB接続安定を待つ）
	select {
	case <-ctx.Done():
		return
	case <-time.After(30 * time.Second):
	}

	r.rebuild(ctx)

	ticker := time.NewTicker(6 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.rebuild(ctx)
		}
	}
}

func (r *BaselineRebuilder) tableExists(ctx context.Context) bool {
	var exists bool
	_ = r.pool.QueryRow(ctx, `
		SELECT EXISTS (
		    SELECT 1 FROM information_schema.tables
		    WHERE table_schema = 'public'
		      AND table_name = 'agent_behavioral_baselines'
		)
	`).Scan(&exists)
	return exists
}

func (r *BaselineRebuilder) rebuild(ctx context.Context) {
	start := time.Now()

	cfg, err := r.bStore.GetConfig(ctx)
	if err != nil {
		slog.Error("ベースライン設定取得エラー", "error", err)
		cfg = &store.BaselineConfig{LearningPeriodDays: 30}
	}

	// アクティブなエージェント一覧を取得
	rows, err := r.pool.Query(ctx, `
		SELECT id::text FROM agents
		WHERE last_seen >= NOW() - INTERVAL '7 days'
		   OR status = 'online'
	`)
	if err != nil {
		slog.Error("エージェント一覧取得エラー", "error", err)
		return
	}
	defer rows.Close()

	var agentIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err == nil {
			agentIDs = append(agentIDs, id)
		}
	}
	rows.Close()

	if len(agentIDs) == 0 {
		slog.Debug("ベースライン再構築: アクティブエージェントなし")
		return
	}

	var succeeded, failed int
	for _, agentID := range agentIDs {
		// 既存の除外ルールを保持する
		exclusionRules := r.bStore.GetExclusionRules(ctx, agentID)

		baseline, err := r.engine.BuildEnrichedBaseline(
			ctx,
			agentID,
			cfg.LearningPeriodDays,
			exclusionRules,
		)
		if err != nil {
			slog.Debug("ベースライン構築エラー", "agent_id", agentID, "error", err)
			failed++
			continue
		}

		if err := r.bStore.Upsert(ctx, baseline); err != nil {
			slog.Debug("ベースライン保存エラー", "agent_id", agentID, "error", err)
			failed++
			continue
		}
		succeeded++
	}

	slog.Info("ベースライン再構築完了",
		"agents_total", len(agentIDs),
		"succeeded", succeeded,
		"failed", failed,
		"elapsed", time.Since(start).Round(time.Millisecond),
	)
}
