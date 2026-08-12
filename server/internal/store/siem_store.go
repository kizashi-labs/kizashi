package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// SIEMTarget represents one SIEM forwarding destination.
type SIEMTarget struct {
	ID              string    `json:"id"`
	Name            string    `json:"name" binding:"required"`
	Type            string    `json:"type" binding:"required"`
	Host            string    `json:"host" binding:"required"`
	Port            int       `json:"port"`
	Protocol        string    `json:"protocol"`
	Token           string    `json:"token,omitempty"`
	TLSEnabled      bool      `json:"tls_enabled"`
	IndexName       string    `json:"index_name"`
	Enabled         bool      `json:"enabled"`
	MinSeverity     int       `json:"min_severity"`
	FilterRules     []string  `json:"filter_rules"`     // 空=全ルール対象、非空=ホワイトリスト
	FilterHostnames []string  `json:"filter_hostnames"` // 空=全端末対象、非空=ホワイトリスト
	FilterMitre     []string  `json:"filter_mitre"`     // 空=全MITREテクニック対象、非空=ホワイトリスト
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// SIEMStore handles SIEM target persistence.
type SIEMStore struct {
	pool *pgxpool.Pool
}

// NewSIEMStore creates a new SIEMStore.
func NewSIEMStore(db *DB) *SIEMStore {
	return &SIEMStore{pool: db.Pool()}
}

// List returns all SIEM targets.
func (s *SIEMStore) List(ctx context.Context) ([]*SIEMTarget, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, name, type, host, port, protocol, token,
		       tls_enabled, index_name, enabled, min_severity,
		       filter_rules, filter_hostnames, filter_mitre,
		       created_at, updated_at
		FROM siem_targets ORDER BY name ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var targets []*SIEMTarget
	for rows.Next() {
		t := &SIEMTarget{}
		if err := rows.Scan(
			&t.ID, &t.Name, &t.Type, &t.Host, &t.Port, &t.Protocol,
			&t.Token, &t.TLSEnabled, &t.IndexName, &t.Enabled, &t.MinSeverity,
			&t.FilterRules, &t.FilterHostnames, &t.FilterMitre,
			&t.CreatedAt, &t.UpdatedAt,
		); err != nil {
			continue
		}
		targets = append(targets, t)
	}
	if targets == nil {
		targets = []*SIEMTarget{}
	}
	return targets, rows.Err()
}

// Create inserts a new SIEM target.
func (s *SIEMStore) Create(ctx context.Context, t *SIEMTarget) (*SIEMTarget, error) {
	out := &SIEMTarget{}
	if t.FilterRules == nil {
		t.FilterRules = []string{}
	}
	if t.FilterHostnames == nil {
		t.FilterHostnames = []string{}
	}
	if t.FilterMitre == nil {
		t.FilterMitre = []string{}
	}
	err := s.pool.QueryRow(ctx, `
		INSERT INTO siem_targets (name, type, host, port, protocol, token, tls_enabled, index_name, enabled, min_severity, filter_rules, filter_hostnames, filter_mitre)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
		RETURNING id, name, type, host, port, protocol, token, tls_enabled, index_name, enabled, min_severity, filter_rules, filter_hostnames, filter_mitre, created_at, updated_at`,
		t.Name, t.Type, t.Host, t.Port, t.Protocol, t.Token,
		t.TLSEnabled, t.IndexName, t.Enabled, t.MinSeverity,
		t.FilterRules, t.FilterHostnames, t.FilterMitre,
	).Scan(
		&out.ID, &out.Name, &out.Type, &out.Host, &out.Port, &out.Protocol,
		&out.Token, &out.TLSEnabled, &out.IndexName, &out.Enabled, &out.MinSeverity,
		&out.FilterRules, &out.FilterHostnames, &out.FilterMitre,
		&out.CreatedAt, &out.UpdatedAt,
	)
	return out, err
}

// Update modifies an existing SIEM target.
func (s *SIEMStore) Update(ctx context.Context, id string, t *SIEMTarget) (*SIEMTarget, error) {
	out := &SIEMTarget{}
	if t.FilterRules == nil {
		t.FilterRules = []string{}
	}
	if t.FilterHostnames == nil {
		t.FilterHostnames = []string{}
	}
	if t.FilterMitre == nil {
		t.FilterMitre = []string{}
	}
	err := s.pool.QueryRow(ctx, `
		UPDATE siem_targets SET
		    name=$1, type=$2, host=$3, port=$4, protocol=$5, token=$6,
		    tls_enabled=$7, index_name=$8, enabled=$9, min_severity=$10,
		    filter_rules=$11, filter_hostnames=$12, filter_mitre=$13,
		    updated_at=NOW()
		WHERE id=$14::uuid
		RETURNING id, name, type, host, port, protocol, token, tls_enabled, index_name, enabled, min_severity, filter_rules, filter_hostnames, filter_mitre, created_at, updated_at`,
		t.Name, t.Type, t.Host, t.Port, t.Protocol, t.Token,
		t.TLSEnabled, t.IndexName, t.Enabled, t.MinSeverity,
		t.FilterRules, t.FilterHostnames, t.FilterMitre, id,
	).Scan(
		&out.ID, &out.Name, &out.Type, &out.Host, &out.Port, &out.Protocol,
		&out.Token, &out.TLSEnabled, &out.IndexName, &out.Enabled, &out.MinSeverity,
		&out.FilterRules, &out.FilterHostnames, &out.FilterMitre,
		&out.CreatedAt, &out.UpdatedAt,
	)
	return out, err
}

// Delete removes a SIEM target.
func (s *SIEMStore) Delete(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM siem_targets WHERE id=$1::uuid`, id)
	return err
}
