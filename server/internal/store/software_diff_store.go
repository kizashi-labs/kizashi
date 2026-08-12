package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// SoftwareDiff represents a daily software inventory diff for an agent.
type SoftwareDiff struct {
	ID           string          `json:"id"`
	AgentID      string          `json:"agent_id"`
	DiffDate     string          `json:"diff_date"`
	Added        json.RawMessage `json:"added"`
	Removed      json.RawMessage `json:"removed"`
	AddedCount   int             `json:"added_count"`
	RemovedCount int             `json:"removed_count"`
	CreatedAt    time.Time       `json:"created_at"`
}

// SoftwareDiffStore handles software inventory diff persistence.
type SoftwareDiffStore struct {
	pool *pgxpool.Pool
}

// NewSoftwareDiffStore creates a SoftwareDiffStore.
func NewSoftwareDiffStore(pool *pgxpool.Pool) *SoftwareDiffStore {
	return &SoftwareDiffStore{pool: pool}
}

func (s *SoftwareDiffStore) tableExists(ctx context.Context, tableName string) bool {
	var exists bool
	_ = s.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name=$1)`,
		tableName,
	).Scan(&exists)
	return exists
}

// GetDiffs returns software_inventory_diffs for the given agent, newest first.
func (s *SoftwareDiffStore) GetDiffs(ctx context.Context, agentID string, limit int) ([]SoftwareDiff, error) {
	if !s.tableExists(ctx, "software_inventory_diffs") {
		return []SoftwareDiff{}, nil
	}
	if limit <= 0 {
		limit = 30
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, agent_id, diff_date::text, added, removed, added_count, removed_count, created_at
		FROM software_inventory_diffs
		WHERE agent_id = $1
		ORDER BY diff_date DESC
		LIMIT $2`,
		agentID, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var diffs []SoftwareDiff
	for rows.Next() {
		var d SoftwareDiff
		if err := rows.Scan(&d.ID, &d.AgentID, &d.DiffDate, &d.Added, &d.Removed,
			&d.AddedCount, &d.RemovedCount, &d.CreatedAt); err != nil {
			continue
		}
		diffs = append(diffs, d)
	}
	if diffs == nil {
		diffs = []SoftwareDiff{}
	}
	return diffs, nil
}

// GetLatestDiff returns the most recent diff for the agent.
func (s *SoftwareDiffStore) GetLatestDiff(ctx context.Context, agentID string) (*SoftwareDiff, error) {
	if !s.tableExists(ctx, "software_inventory_diffs") {
		return nil, nil
	}
	var d SoftwareDiff
	err := s.pool.QueryRow(ctx, `
		SELECT id, agent_id, diff_date::text, added, removed, added_count, removed_count, created_at
		FROM software_inventory_diffs
		WHERE agent_id = $1
		ORDER BY diff_date DESC
		LIMIT 1`,
		agentID,
	).Scan(&d.ID, &d.AgentID, &d.DiffDate, &d.Added, &d.Removed,
		&d.AddedCount, &d.RemovedCount, &d.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &d, nil
}

// CreateSnapshot upserts a software inventory snapshot for the agent.
func (s *SoftwareDiffStore) CreateSnapshot(ctx context.Context, agentID string, software []map[string]interface{}) error {
	if !s.tableExists(ctx, "software_inventory_snapshots") {
		return nil
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO software_inventory_snapshots (agent_id, snapshot_date, software_count)
		VALUES ($1, CURRENT_DATE, $2)
		ON CONFLICT (agent_id, snapshot_date)
		DO UPDATE SET software_count = EXCLUDED.software_count`,
		agentID, len(software),
	)
	return err
}
