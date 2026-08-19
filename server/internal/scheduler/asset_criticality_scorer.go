package scheduler

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// AssetCriticalityScorer periodically derives a 0-100 criticality score for each
// agent and stores it in asset_criticality_scores. The score is derived
// entirely from data the server already has — the agent's tags plus its open
// critical alerts and critical/high vulnerabilities — so no agent changes are
// needed. It also turns the compliance scorer's "asset criticality classified"
// evidence check (COUNT(*) > 0) into real data.
type AssetCriticalityScorer struct {
	pool *pgxpool.Pool
}

func NewAssetCriticalityScorer(pool *pgxpool.Pool) *AssetCriticalityScorer {
	return &AssetCriticalityScorer{pool: pool}
}

func (s *AssetCriticalityScorer) Run(ctx context.Context) {
	// Run once shortly after start, then every 6 hours.
	trackRun(ctx, "asset_criticality_scorer", s.calculate)
	ticker := time.NewTicker(6 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			trackRun(ctx, "asset_criticality_scorer", s.calculate)
		}
	}
}

// tagCriticalityBase returns the base criticality contributed by an agent's
// tags. High-value asset classes (domain controllers, servers, databases,
// production) weigh more; anything tagged at all beats an untagged endpoint.
func tagCriticalityBase(tags []string) int {
	base := 10
	for _, t := range tags {
		switch strings.ToLower(strings.TrimSpace(t)) {
		case "domain_controller", "dc", "domain-controller":
			if base < 45 {
				base = 45
			}
		case "server", "database", "db", "production", "prod", "critical":
			if base < 30 {
				base = 30
			}
		case "workstation", "laptop", "desktop":
			if base < 15 {
				base = 15
			}
		}
	}
	return base
}

func (s *AssetCriticalityScorer) calculate(ctx context.Context) {
	var exists bool
	if err := s.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables
		   WHERE table_schema='public' AND table_name='asset_criticality_scores')`).Scan(&exists); err != nil || !exists {
		fail(ctx, err, "asset_criticality_scores テーブルが存在しません、スキップします")
		return
	}

	// Gather per-agent signals in one pass. Alert severity is on the 1-10 scale
	// (critical >= 9); vulnerability severity is a text label.
	rows, err := s.pool.Query(ctx, `
		SELECT a.id::text,
		       COALESCE(a.tags, '{}'),
		       -- 'closed' は incidents の語彙で、alerts.status の CHECK
		       -- (open|investigating|resolved|false_positive|auto_resolved) には無い。
		       -- 除外したかったのは自動クローズ分なので 'auto_resolved'。以前の綴りでは
		       -- この枝が一度も一致せず、自動解決済みのクリティカルアラートが
		       -- 資産重要度スコアを押し上げ続けていた。
		       COUNT(al.id) FILTER (WHERE al.severity >= 9
		           AND al.status NOT IN ('resolved','false_positive','auto_resolved')) AS crit_alerts,
		       COUNT(v.id)  FILTER (WHERE v.severity = 'critical' AND v.status = 'open') AS crit_vulns,
		       COUNT(v.id)  FILTER (WHERE v.severity = 'high'     AND v.status = 'open') AS high_vulns
		FROM agents a
		LEFT JOIN alerts al          ON al.agent_id = a.id
		LEFT JOIN vulnerabilities v  ON v.agent_id = a.id
		GROUP BY a.id, a.tags`)
	if err != nil {
		fail(ctx, err, "資産重要度スコア: エージェント集計に失敗")
		return
	}
	defer rows.Close()

	type agentScore struct {
		id      string
		score   int
		factors map[string]int
	}
	var scored []agentScore
	for rows.Next() {
		var id string
		var tags []string
		var critAlerts, critVulns, highVulns int
		if err := rows.Scan(&id, &tags, &critAlerts, &critVulns, &highVulns); err != nil {
			continue
		}
		base := tagCriticalityBase(tags)
		score := base + critAlerts*5 + critVulns*10 + highVulns*3
		if score > 100 {
			score = 100
		}
		scored = append(scored, agentScore{
			id:    id,
			score: score,
			factors: map[string]int{
				"tag_base": base, "crit_alerts": critAlerts,
				"crit_vulns": critVulns, "high_vulns": highVulns,
			},
		})
	}
	if err := rows.Err(); err != nil {
		fail(ctx, err, "資産重要度スコア: 行スキャンに失敗")
		return
	}

	for _, a := range scored {
		factorsJSON, _ := json.Marshal(a.factors)
		if _, err := s.pool.Exec(ctx, `
			INSERT INTO asset_criticality_scores (agent_id, score, factors, calculated_at)
			VALUES ($1::uuid, $2, $3::jsonb, NOW())
			ON CONFLICT (agent_id) DO UPDATE SET
				score = EXCLUDED.score,
				factors = EXCLUDED.factors,
				calculated_at = NOW()`,
			a.id, a.score, string(factorsJSON)); err != nil {
			fail(ctx, err, "資産重要度スコアの保存に失敗", "agent", a.id)
		}
	}
	slog.Info("資産重要度スコアを更新しました", "agents", len(scored))
}
