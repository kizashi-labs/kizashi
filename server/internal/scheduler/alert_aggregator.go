package scheduler

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// AlertAggregator deduplicates repeated alerts by grouping them under a parent.
type AlertAggregator struct {
	pool *pgxpool.Pool
}

// NewAlertAggregator creates a new AlertAggregator.
func NewAlertAggregator(pool *pgxpool.Pool) *AlertAggregator {
	return &AlertAggregator{pool: pool}
}

// Run starts the aggregation loop, running every 5 minutes until ctx is cancelled.
func (a *AlertAggregator) Run(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.aggregate(ctx)
		}
	}
}

func (a *AlertAggregator) aggregate(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("alert_aggregator: panic recovered", "err", r)
		}
	}()

	// Check if parent_id column exists on alerts table.
	var hasParentID bool
	err := a.pool.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM information_schema.columns
			WHERE table_name = 'alerts' AND column_name = 'parent_id'
		)
	`).Scan(&hasParentID)
	if err != nil {
		slog.Error("alert_aggregator: checking parent_id column", "err", err)
		return
	}
	if !hasParentID {
		return
	}

	// Find groups of >=3 alerts with the same title+agent_id in the last 10 minutes
	// that have no parent_id set. The oldest alert in each group becomes the parent.
	rows, err := a.pool.Query(ctx, `
		SELECT
			MIN(id)::text AS parent_id,
			array_agg(id::text ORDER BY created_at) AS all_ids
		FROM alerts
		WHERE created_at >= NOW() - INTERVAL '10 minutes'
		  AND parent_id IS NULL
		  AND title IS NOT NULL
		  AND agent_id IS NOT NULL
		GROUP BY title, agent_id
		HAVING COUNT(*) >= 3
	`)
	if err != nil {
		slog.Error("alert_aggregator: querying duplicate groups", "err", err)
		return
	}
	defer rows.Close()

	type group struct {
		parentID string
		allIDs   []string
	}
	var groups []group
	for rows.Next() {
		var g group
		if err := rows.Scan(&g.parentID, &g.allIDs); err != nil {
			continue
		}
		groups = append(groups, g)
	}
	rows.Close()

	updated := 0
	for _, g := range groups {
		// Set parent_id on all duplicates (everything except the parent itself).
		duplicates := []string{}
		for _, id := range g.allIDs {
			if id != g.parentID {
				duplicates = append(duplicates, id)
			}
		}
		if len(duplicates) == 0 {
			continue
		}

		tag, err := a.pool.Exec(ctx, `
			UPDATE alerts
			SET parent_id = $1
			WHERE id = ANY($2::uuid[]) AND parent_id IS NULL
		`, g.parentID, duplicates)
		if err != nil {
			slog.Error("alert_aggregator: updating parent_id", "parent", g.parentID, "err", err)
			continue
		}
		updated += int(tag.RowsAffected())
	}

	if updated > 0 {
		slog.Info("alert_aggregator: grouped duplicate alerts", "updated", updated, "groups", len(groups))
	}
}
