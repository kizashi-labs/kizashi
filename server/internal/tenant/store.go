// Package tenant provides multi-tenant organization management with data isolation.
package tenant

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Organization represents a tenant organization.
type Organization struct {
	ID         string      `json:"id"`
	Name       string      `json:"name" binding:"required"`
	Slug       string      `json:"slug"`
	Plan       string      `json:"plan"`
	AgentLimit int         `json:"agent_limit"`
	UserLimit  int         `json:"user_limit"`
	Enabled    bool        `json:"enabled"`
	Settings   OrgSettings `json:"settings"`
	CreatedAt  time.Time   `json:"created_at"`
}

// OrgSettings holds per-organization customization.
type OrgSettings struct {
	AllowSSO      bool   `json:"allow_sso"`
	RetentionDays int    `json:"retention_days"`
	LogoURL       string `json:"logo_url"`
	PrimaryColor  string `json:"primary_color"`
}

// OrgStats holds aggregate statistics for an organization.
type OrgStats struct {
	AgentCount    int   `json:"agent_count"`
	UserCount     int   `json:"user_count"`
	AlertCount30d int   `json:"alert_count_30d"`
	StorageMB     int64 `json:"storage_mb"`
}

// Store manages organizations in the database.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore creates a new organization Store.
func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// Create inserts a new organization and returns it with its generated ID.
func (s *Store) Create(ctx context.Context, org *Organization) (*Organization, error) {
	settingsJSON, err := json.Marshal(org.Settings)
	if err != nil {
		settingsJSON = []byte("{}")
	}

	var id string
	var createdAt time.Time
	err = s.pool.QueryRow(ctx,
		`INSERT INTO organizations (name, slug, plan, agent_limit, user_limit, enabled, settings)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)
		 RETURNING id, created_at`,
		org.Name, org.Slug, org.Plan, org.AgentLimit, org.UserLimit, org.Enabled, settingsJSON,
	).Scan(&id, &createdAt)
	if err != nil {
		return nil, err
	}
	org.ID = id
	org.CreatedAt = createdAt
	return org, nil
}

// Get retrieves an organization by ID.
func (s *Store) Get(ctx context.Context, id string) (*Organization, error) {
	return s.scanOne(ctx,
		`SELECT id, name, slug, plan, agent_limit, user_limit, enabled, settings, created_at
		 FROM organizations WHERE id = $1`, id)
}

// GetBySlug retrieves an organization by its slug.
func (s *Store) GetBySlug(ctx context.Context, slug string) (*Organization, error) {
	return s.scanOne(ctx,
		`SELECT id, name, slug, plan, agent_limit, user_limit, enabled, settings, created_at
		 FROM organizations WHERE slug = $1`, slug)
}

// List returns all organizations.
func (s *Store) List(ctx context.Context) ([]*Organization, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, name, slug, plan, agent_limit, user_limit, enabled, settings, created_at
		 FROM organizations ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var orgs []*Organization
	for rows.Next() {
		org, err := s.scanRow(rows)
		if err != nil {
			slog.Warn("tenant: scan org row failed", "err", err)
			continue
		}
		orgs = append(orgs, org)
	}
	if orgs == nil {
		orgs = []*Organization{}
	}
	return orgs, nil
}

// Update modifies an existing organization.
func (s *Store) Update(ctx context.Context, id string, org *Organization) (*Organization, error) {
	settingsJSON, err := json.Marshal(org.Settings)
	if err != nil {
		settingsJSON = []byte("{}")
	}

	_, err = s.pool.Exec(ctx,
		`UPDATE organizations SET name=$1, slug=$2, plan=$3, agent_limit=$4, user_limit=$5,
		 enabled=$6, settings=$7, updated_at=NOW()
		 WHERE id=$8`,
		org.Name, org.Slug, org.Plan, org.AgentLimit, org.UserLimit, org.Enabled, settingsJSON, id)
	if err != nil {
		return nil, err
	}
	return s.Get(ctx, id)
}

// Delete removes an organization by ID.
func (s *Store) Delete(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM organizations WHERE id = $1`, id)
	return err
}

// GetStats returns aggregate statistics for an organization.
//
// agents / users / alerts の所属列は tenant_id で、org_id は存在しない。
// 以前は org_id で数えており、3 本とも毎回
// `column "org_id" does not exist` で失敗していた。戻り値を `_ =` で
// 捨てているため、組織統計は常に 0/0/0 を返していた
// (/api/v1 の組織詳細から到達する)。
//
// 注意: organizations と tenants は列構成が重なる別テーブルで、
// tenant_id の外部キーは tenants を指す。両者を突き合わせられるのは
// migration 183 が入れる既定組織と既定テナントが同じ UUID
// (00000000-0000-0000-0000-000000000001) を持つためで、
// Store.Create で新規に作った組織には対応するテナントが無い。
// その場合ここは 0 を返すが、実際にその組織を参照するエージェントも
// 存在しないので数としては正しい。
// 概念の重複そのものは別途整理が要る。
func (s *Store) GetStats(ctx context.Context, orgID string) (*OrgStats, error) {
	stats := &OrgStats{}

	// Agent count
	if err := s.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM agents WHERE tenant_id = $1`, orgID,
	).Scan(&stats.AgentCount); err != nil {
		slog.Warn("tenant: エージェント数の取得に失敗", "org_id", orgID, "error", err)
	}

	// User count
	if err := s.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM users WHERE tenant_id = $1`, orgID,
	).Scan(&stats.UserCount); err != nil {
		slog.Warn("tenant: ユーザー数の取得に失敗", "org_id", orgID, "error", err)
	}

	// Alert count last 30 days
	if err := s.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM alerts WHERE tenant_id = $1 AND created_at > NOW() - INTERVAL '30 days'`, orgID,
	).Scan(&stats.AlertCount30d); err != nil {
		slog.Warn("tenant: アラート数の取得に失敗", "org_id", orgID, "error", err)
	}

	return stats, nil
}

// scanOne is a helper that runs a query expecting a single organization row.
func (s *Store) scanOne(ctx context.Context, query string, args ...interface{}) (*Organization, error) {
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, errors.New("not found")
	}
	return s.scanRow(rows)
}

type scanner interface {
	Scan(dest ...interface{}) error
}

func (s *Store) scanRow(row scanner) (*Organization, error) {
	var org Organization
	var settingsJSON []byte
	err := row.Scan(
		&org.ID, &org.Name, &org.Slug, &org.Plan,
		&org.AgentLimit, &org.UserLimit, &org.Enabled,
		&settingsJSON, &org.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	if len(settingsJSON) > 0 {
		_ = json.Unmarshal(settingsJSON, &org.Settings)
	}
	return &org, nil
}
