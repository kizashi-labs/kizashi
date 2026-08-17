package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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
	return TableIsThere(ctx, s.pool, tableName)
}

// GetDiffs returns software_inventory_diffs for the given agent, newest first.
func (s *SoftwareDiffStore) GetDiffs(ctx context.Context, agentID string, limit int) ([]SoftwareDiff, error) {
	if !s.tableExists(ctx, "software_inventory_diffs") {
		return []SoftwareDiff{}, nil
	}
	if limit <= 0 {
		limit = 30
	}
	// agent_id は uuid 列。呼び出し元がパスパラメータをそのまま渡すため空文字が
	// 来ることがあり、'' を uuid にキャストすると SQLSTATE 22P02 になる。
	// 以前はそのエラーが握り潰されて 200 + 空配列に見えていた。
	// NULLIF で「エージェント未指定 = 該当なし」に正規化する。
	rows, err := s.pool.Query(ctx, `
		SELECT id, agent_id, diff_date::text, added, removed, added_count, removed_count, created_at
		FROM software_inventory_diffs
		WHERE agent_id = NULLIF($1,'')::uuid
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
	// 部分結果を完全な一覧として返さない（scan_truncation_guard_test.go 参照）
	if err := rows.Err(); err != nil {
		return nil, err
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
		WHERE agent_id = NULLIF($1,'')::uuid
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

// SoftwareItem is one installed package, as a snapshot stores it.
type SoftwareItem struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Key identifies a package for diffing. Name alone is not enough: an upgrade is
// a removal plus an addition, and that is the change worth telling an analyst
// about.
func (s SoftwareItem) Key() string { return s.Name + "@" + s.Version }

// snapshotExecer is the subset of pgx both a pool and a transaction satisfy, so
// a snapshot can be written inside the transaction that is about to replace the
// inventory it describes.
type snapshotExecer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// RecordSoftwareSnapshot stores what an agent reported today, contents and all.
//
// The column held only software_count, so a snapshot could say how many
// packages were installed but never which — and no production path called the
// writer at all. Meanwhile UpsertBatch deletes the agent's rows before
// re-inserting them, so yesterday's inventory was destroyed on every report.
// Between them there was nothing left to diff against, which is why the diff
// endpoint could only ever answer "nothing changed".
func RecordSoftwareSnapshot(ctx context.Context, ex snapshotExecer, agentID string, items []SoftwareItem) error {
	if items == nil {
		items = []SoftwareItem{}
	}
	payload, err := json.Marshal(items)
	if err != nil {
		return err
	}
	_, err = ex.Exec(ctx, `
		INSERT INTO software_inventory_snapshots (agent_id, snapshot_date, software_count, software)
		VALUES ($1::uuid, CURRENT_DATE, $2, $3)
		ON CONFLICT (agent_id, snapshot_date)
		DO UPDATE SET software_count = EXCLUDED.software_count,
		              software       = EXCLUDED.software`,
		agentID, len(items), payload,
	)
	return err
}

// CreateSnapshot upserts a software inventory snapshot for the agent.
func (s *SoftwareDiffStore) CreateSnapshot(ctx context.Context, agentID string, software []map[string]interface{}) error {
	if !s.tableExists(ctx, "software_inventory_snapshots") {
		return nil
	}
	items := make([]SoftwareItem, 0, len(software))
	for _, sw := range software {
		name, _ := sw["name"].(string)
		version, _ := sw["version"].(string)
		items = append(items, SoftwareItem{Name: name, Version: version})
	}
	return RecordSoftwareSnapshot(ctx, s.pool, agentID, items)
}

// PreviousSnapshot returns the most recent snapshot strictly before today, and
// reports whether one exists. "Before today" rather than "yesterday": an agent
// that was offline over a weekend still needs its changes noticed on Monday,
// and a fixed CURRENT_DATE - 1 lookup silently finds nothing for it.
func (s *SoftwareDiffStore) PreviousSnapshot(ctx context.Context, agentID string) ([]SoftwareItem, bool, error) {
	var payload []byte
	err := s.pool.QueryRow(ctx, `
		SELECT software FROM software_inventory_snapshots
		WHERE agent_id = $1::uuid AND snapshot_date < CURRENT_DATE
		ORDER BY snapshot_date DESC
		LIMIT 1`, agentID).Scan(&payload)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	var items []SoftwareItem
	if err := json.Unmarshal(payload, &items); err != nil {
		return nil, false, err
	}
	return items, true, nil
}

// UpsertDiff stores one day's diff, replacing any earlier computation for the
// same day rather than adding a second row for it.
func (s *SoftwareDiffStore) UpsertDiff(ctx context.Context, agentID string, added, removed []SoftwareItem) (string, error) {
	if added == nil {
		added = []SoftwareItem{}
	}
	if removed == nil {
		removed = []SoftwareItem{}
	}
	addedJSON, err := json.Marshal(added)
	if err != nil {
		return "", err
	}
	removedJSON, err := json.Marshal(removed)
	if err != nil {
		return "", err
	}
	var id string
	err = s.pool.QueryRow(ctx, `
		INSERT INTO software_inventory_diffs
		  (agent_id, diff_date, added, removed, added_count, removed_count)
		VALUES ($1::uuid, CURRENT_DATE, $2, $3, $4, $5)
		ON CONFLICT (agent_id, diff_date) DO UPDATE
		SET added = EXCLUDED.added, removed = EXCLUDED.removed,
		    added_count = EXCLUDED.added_count, removed_count = EXCLUDED.removed_count,
		    created_at = NOW()
		RETURNING id::text`,
		agentID, addedJSON, removedJSON, len(added), len(removed),
	).Scan(&id)
	return id, err
}

// DiffSoftware returns what was added and removed between two inventories.
func DiffSoftware(previous, current []SoftwareItem) (added, removed []SoftwareItem) {
	prevSet := make(map[string]bool, len(previous))
	for _, p := range previous {
		prevSet[p.Key()] = true
	}
	currSet := make(map[string]bool, len(current))
	for _, c := range current {
		currSet[c.Key()] = true
	}
	for _, c := range current {
		if !prevSet[c.Key()] {
			added = append(added, c)
		}
	}
	for _, p := range previous {
		if !currSet[p.Key()] {
			removed = append(removed, p)
		}
	}
	return added, removed
}
