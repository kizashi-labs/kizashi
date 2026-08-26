package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// SoftwareEntry represents one installed application on an endpoint.
type SoftwareEntry struct {
	ID          string    `json:"id"`
	AgentID     string    `json:"agent_id"`
	Name        string    `json:"name"`
	Version     string    `json:"version,omitempty"`
	Vendor      string    `json:"vendor,omitempty"`
	InstallDate string    `json:"install_date,omitempty"`
	InstallPath string    `json:"install_path,omitempty"`
	ReportedAt  time.Time `json:"reported_at"`
}

// SoftwareInventoryStore manages endpoint software inventory.
type SoftwareInventoryStore struct {
	pool *pgxpool.Pool
}

func NewSoftwareInventoryStore(db *DB) *SoftwareInventoryStore {
	return &SoftwareInventoryStore{pool: db.Pool()}
}

// ListByAgent returns all software entries for the given agent.
func (s *SoftwareInventoryStore) ListByAgent(ctx context.Context, agentID string) ([]*SoftwareEntry, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, agent_id::text, name,
		       COALESCE(version,''), COALESCE(vendor,''),
		       COALESCE(install_date,''), COALESCE(install_path,''),
		       reported_at
		FROM endpoint_software
		WHERE agent_id = $1::uuid
		ORDER BY name ASC`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []*SoftwareEntry
	for rows.Next() {
		sw := &SoftwareEntry{}
		if err := rows.Scan(
			&sw.ID, &sw.AgentID, &sw.Name,
			&sw.Version, &sw.Vendor,
			&sw.InstallDate, &sw.InstallPath, &sw.ReportedAt,
		); err != nil {
			continue
		}
		items = append(items, sw)
	}
	// 部分結果を完全な一覧として返さない（scan_truncation_guard_test.go 参照）
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if items == nil {
		items = []*SoftwareEntry{}
	}
	return items, nil
}

// SearchAcrossAgents returns software entries matching name across all endpoints.
func (s *SoftwareInventoryStore) SearchAcrossAgents(ctx context.Context, q string, limit int) ([]*SoftwareEntry, error) {
	if limit == 0 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `
		SELECT sw.id, sw.agent_id::text, sw.name,
		       COALESCE(sw.version,''), COALESCE(sw.vendor,''),
		       COALESCE(sw.install_date,''), COALESCE(sw.install_path,''),
		       sw.reported_at
		FROM endpoint_software sw
		WHERE sw.name ILIKE $1
		ORDER BY sw.name, sw.reported_at DESC
		LIMIT $2`, "%"+q+"%", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []*SoftwareEntry
	for rows.Next() {
		sw := &SoftwareEntry{}
		if err := rows.Scan(
			&sw.ID, &sw.AgentID, &sw.Name,
			&sw.Version, &sw.Vendor,
			&sw.InstallDate, &sw.InstallPath, &sw.ReportedAt,
		); err != nil {
			continue
		}
		items = append(items, sw)
	}
	// 部分結果を完全な一覧として返さない（scan_truncation_guard_test.go 参照）
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if items == nil {
		items = []*SoftwareEntry{}
	}
	return items, nil
}

// UpsertBatch replaces all software for an agent (full refresh from agent report).
func (s *SoftwareInventoryStore) UpsertBatch(ctx context.Context, agentID string, items []*SoftwareEntry) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// Record what this report contains. The refresh below is destructive — every
	// row for the agent is deleted and re-inserted — so without a snapshot there
	// is nothing left of yesterday to compare tomorrow's report against, and the
	// software diff endpoint can only ever answer "nothing changed".
	//
	// Inside the transaction on purpose: a snapshot that survived a failed
	// refresh would describe an inventory the database does not hold. Its
	// position relative to the DELETE is immaterial — the contents come from
	// items, not from the rows being replaced.
	snapshot := make([]SoftwareItem, 0, len(items))
	for _, sw := range items {
		if sw == nil {
			continue
		}
		snapshot = append(snapshot, SoftwareItem{Name: sw.Name, Version: sw.Version})
	}
	if err := RecordSoftwareSnapshot(ctx, tx, agentID, snapshot); err != nil {
		return err
	}

	// Remove old entries for this agent
	if _, err := tx.Exec(ctx,
		"DELETE FROM endpoint_software WHERE agent_id = $1::uuid", agentID,
	); err != nil {
		return err
	}

	for _, sw := range items {
		if _, err := tx.Exec(ctx, `
			INSERT INTO endpoint_software
			  (agent_id, name, version, vendor, install_date, install_path)
			VALUES ($1::uuid, $2, $3, $4, $5, $6)
			ON CONFLICT (agent_id, name, version) DO UPDATE
			SET vendor=$4, install_date=$5, install_path=$6, reported_at=NOW()`,
			agentID, sw.Name, sw.Version, sw.Vendor, sw.InstallDate, sw.InstallPath,
		); err != nil {
			// 入らなかった行を飛ばして Commit すると、この関数は成功を
			// 返します。ソフトウェア一覧は脆弱性の突き合わせ元なので、
			// 入らなかった分だけ「入っていないソフト」になります。
			return fmt.Errorf("ソフトウェア %s %s を記録できませんでした: %w", sw.Name, sw.Version, err)
		}
	}
	return tx.Commit(ctx)
}

// DeleteEntry removes a single software entry.
func (s *SoftwareInventoryStore) DeleteEntry(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, "DELETE FROM endpoint_software WHERE id=$1", id)
	return err
}
