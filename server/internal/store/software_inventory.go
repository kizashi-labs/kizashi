package store

import (
	"context"
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
			continue
		}
	}
	return tx.Commit(ctx)
}

// DeleteEntry removes a single software entry.
func (s *SoftwareInventoryStore) DeleteEntry(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, "DELETE FROM endpoint_software WHERE id=$1", id)
	return err
}
