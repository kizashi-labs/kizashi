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

	trackRun(ctx, "baseline_rebuilder", r.rebuild)

	ticker := time.NewTicker(6 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			trackRun(ctx, "baseline_rebuilder", r.rebuild)
		}
	}
}

func (r *BaselineRebuilder) tableExists(ctx context.Context) bool {
	return store.TableIsThere(ctx, r.pool, "agent_behavioral_baselines")
}

func (r *BaselineRebuilder) rebuild(ctx context.Context) {
	start := time.Now()

	cfg, err := r.bStore.GetConfig(ctx)
	if err != nil {
		// 既定の30日で作り直すと、7日や90日を設定したテナントでは、
		// 誰も選んでいない期間のベースラインが保存されます。以後の
		// 逸脱判定はその土台の上で行われます。次の周回でやり直せるので、
		// 作らずに戻ります。
		fail(ctx, err, "ベースライン再構築: 設定を読めないため今回は作り直しません")
		return
	}

	// アクティブなエージェント一覧を取得
	rows, err := r.pool.Query(ctx, `
		SELECT id::text FROM agents
		WHERE last_seen >= NOW() - INTERVAL '7 days'
		   OR status = 'online'
	`)
	if err != nil {
		fail(ctx, err, "エージェント一覧取得エラー")
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
	if err := rows.Err(); err != nil {
		fail(ctx, err, "エージェント一覧の走査が途中で終わりました。今回のパスでベースラインを再構築しないエージェントがあります")
	}
	rows.Close()

	if len(agentIDs) == 0 {
		slog.Debug("ベースライン再構築: アクティブエージェントなし")
		return
	}

	var succeeded, failed int
	for _, agentID := range agentIDs {
		// 既存の除外ルールを保持する。読めないまま再構築すると、
		// 除外ルールが空のベースラインで上書きしてしまいます。
		exclusionRules, err := r.bStore.GetExclusionRules(ctx, agentID)
		if err != nil {
			fail(ctx, err, "ベースライン再構築: 除外ルールを読めないため飛ばしました",
				"agent_id", agentID)
			failed++
			continue
		}

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
