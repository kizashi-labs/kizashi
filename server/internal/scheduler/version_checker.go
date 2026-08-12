package scheduler

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// VersionChecker periodically checks agent version distribution across online agents.
type VersionChecker struct {
	pool     *pgxpool.Pool
	client   *http.Client
	interval time.Duration
}

func NewVersionChecker(pool *pgxpool.Pool) *VersionChecker {
	return &VersionChecker{
		pool:     pool,
		client:   &http.Client{Timeout: 10 * time.Second},
		interval: 6 * time.Hour,
	}
}

func (v *VersionChecker) Run(ctx context.Context) {
	ticker := time.NewTicker(v.interval)
	defer ticker.Stop()
	slog.Info("エージェントバージョンチェッカー起動")
	v.check(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			v.check(ctx)
		}
	}
}

func (v *VersionChecker) check(ctx context.Context) {
	// Count agents running each version (top 10 by count).
	//
	// 列名は agent_version。version という列は agents に存在せず、この
	// クエリは毎回 "column \"version\" does not exist" で失敗していた。
	// err を握って return するだけなので、バージョン分布は一度も出て
	// いなかった (system_metadata への保存もそこへ到達しない)。
	rows, err := v.pool.Query(ctx,
		`SELECT agent_version, COUNT(*) FROM agents
         WHERE agent_version IS NOT NULL AND status='online'
         GROUP BY agent_version ORDER BY COUNT(*) DESC LIMIT 10`)
	if err != nil {
		return
	}
	defer rows.Close()

	versionCounts := map[string]int{}
	for rows.Next() {
		var version string
		var count int
		if err := rows.Scan(&version, &count); err == nil {
			versionCounts[version] = count
		}
	}

	if len(versionCounts) > 0 {
		slog.Info("エージェントバージョン分布", "versions", versionCounts)
	}

	// Attempt to persist summary in DB for the admin UI.
	// The system_metadata table is optional; if it does not exist the
	// upsert will fail silently — this is intentional.
	summary, _ := json.Marshal(versionCounts)
	_, _ = v.pool.Exec(ctx,
		`INSERT INTO system_metadata (key, value, updated_at)
         VALUES ('agent_version_distribution', $1, NOW())
         ON CONFLICT (key) DO UPDATE SET value=$1, updated_at=NOW()`,
		string(summary),
	)
}
