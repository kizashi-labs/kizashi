package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// UninstallGuard is the tenant's uninstall-password material. It never carries
// the password itself — only the PBKDF2 salt and digest the agent verifies
// against. See agent/internal/uninstallguard for the matching derivation.
type UninstallGuard struct {
	TenantID   string    `json:"tenant_id"`
	Version    int       `json:"version"`
	Algorithm  string    `json:"algorithm"`
	Iterations int       `json:"iterations"`
	SaltB64    string    `json:"salt"`
	DigestB64  string    `json:"digest"`
	UpdatedAt  time.Time `json:"updated_at"`
	UpdatedBy  string    `json:"updated_by,omitempty"`
}

// UninstallAttempt records that someone tried to remove an agent.
type UninstallAttempt struct {
	ID         int64     `json:"id"`
	TenantID   string    `json:"tenant_id"`
	AgentID    string    `json:"agent_id,omitempty"`
	Hostname   string    `json:"hostname,omitempty"`
	Authorised bool      `json:"authorised"`
	OccurredAt time.Time `json:"occurred_at"`
	CreatedAt  time.Time `json:"created_at"`
}

// ErrNoUninstallGuard means the tenant has not set an uninstall password.
var ErrNoUninstallGuard = errors.New("no uninstall guard configured for tenant")

// UninstallProtectionStore persists uninstall-password material and attempts.
type UninstallProtectionStore struct {
	pool *pgxpool.Pool
}

// NewUninstallProtectionStore creates a store backed by the given pool.
func NewUninstallProtectionStore(pool *pgxpool.Pool) *UninstallProtectionStore {
	return &UninstallProtectionStore{pool: pool}
}

// ErrAgentTenantUnknown means the agent is not registered (or carries no
// tenant), so no tenant can be pinned for it.
var ErrAgentTenantUnknown = errors.New("agent has no known tenant")

// TenantOfAgent returns the tenant the agent belongs to.
//
// **エージェント向けの経路はテナントを名乗りません。** ハートビートも
// アンインストール試行の通報も認証なしで、名乗るのは利用者ではなく端末
// です。それでもテナントは決まります —— 端末の行が持っているからです。
// ここで引いて `app.tenant_id` に張ることで、uninstall_guards /
// uninstall_attempts の RLS から「未設定なら全テナント可」の抜け道を
// 落とせます。
//
// agents 側の方針は抜け道を残したままなので、この引き当て自体は
// テナント未設定の接続でも通ります。
func (s *UninstallProtectionStore) TenantOfAgent(ctx context.Context, agentID string) (string, error) {
	if agentID == "" {
		return "", ErrAgentTenantUnknown
	}
	var tenantID string
	err := s.pool.QueryRow(ctx,
		`SELECT COALESCE(tenant_id::text, '') FROM agents WHERE id = $1::uuid`,
		agentID).Scan(&tenantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrAgentTenantUnknown
	}
	if err != nil {
		return "", fmt.Errorf("tenant of agent: %w", err)
	}
	if tenantID == "" {
		return "", ErrAgentTenantUnknown
	}
	return tenantID, nil
}

// GetGuard returns the tenant's guard material, or ErrNoUninstallGuard when the
// tenant has not set a password.
//
// The distinction matters at the call site: "no password set" means agents are
// told nothing and uninstalls proceed, whereas a query failure must not be
// allowed to look the same. Silently degrading to "unprotected" on a transient
// DB error would disable the protection fleet-wide for the duration.
func (s *UninstallProtectionStore) GetGuard(ctx context.Context, tenantID string) (*UninstallGuard, error) {
	var g UninstallGuard
	err := s.pool.QueryRow(ctx, `
		SELECT tenant_id::text, version, algorithm, iterations, salt, digest,
		       updated_at, COALESCE(updated_by, '')
		  FROM uninstall_guards
		 WHERE tenant_id = $1::uuid`, tenantID).
		Scan(&g.TenantID, &g.Version, &g.Algorithm, &g.Iterations,
			&g.SaltB64, &g.DigestB64, &g.UpdatedAt, &g.UpdatedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNoUninstallGuard
	}
	if err != nil {
		return nil, fmt.Errorf("get uninstall guard: %w", err)
	}
	return &g, nil
}

// SetGuard installs or rotates the tenant's guard material.
//
// Rotation is a plain upsert: the previous digest is replaced, not versioned.
// Keeping old digests would mean old passwords keep working somewhere, which is
// the opposite of what rotating one is for.
func (s *UninstallProtectionStore) SetGuard(ctx context.Context, g *UninstallGuard) error {
	if g == nil {
		return errors.New("nil guard")
	}
	if g.SaltB64 == "" || g.DigestB64 == "" || g.Iterations <= 0 {
		return errors.New("guard material is incomplete")
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO uninstall_guards
		    (tenant_id, version, algorithm, iterations, salt, digest, updated_at, updated_by)
		VALUES ($1::uuid, $2, $3, $4, $5, $6, NOW(), $7)
		ON CONFLICT (tenant_id) DO UPDATE SET
		    version    = EXCLUDED.version,
		    algorithm  = EXCLUDED.algorithm,
		    iterations = EXCLUDED.iterations,
		    salt       = EXCLUDED.salt,
		    digest     = EXCLUDED.digest,
		    updated_at = NOW(),
		    updated_by = EXCLUDED.updated_by`,
		g.TenantID, g.Version, g.Algorithm, g.Iterations,
		g.SaltB64, g.DigestB64, nullIfEmpty(g.UpdatedBy))
	if err != nil {
		return fmt.Errorf("set uninstall guard: %w", err)
	}
	return nil
}

// ClearGuard removes the tenant's uninstall password, returning the fleet to
// unprotected uninstalls.
func (s *UninstallProtectionStore) ClearGuard(ctx context.Context, tenantID string) error {
	_, err := s.pool.Exec(ctx,
		`DELETE FROM uninstall_guards WHERE tenant_id = $1::uuid`, tenantID)
	if err != nil {
		return fmt.Errorf("clear uninstall guard: %w", err)
	}
	return nil
}

// RecordAttempt stores one uninstall attempt.
func (s *UninstallProtectionStore) RecordAttempt(ctx context.Context, a *UninstallAttempt) error {
	if a == nil {
		return errors.New("nil attempt")
	}
	occurred := a.OccurredAt
	if occurred.IsZero() {
		occurred = time.Now().UTC()
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO uninstall_attempts
		    (tenant_id, agent_id, hostname, authorised, occurred_at)
		VALUES ($1::uuid, $2::uuid, $3, $4, $5)`,
		a.TenantID, nullIfEmpty(a.AgentID), nullIfEmpty(a.Hostname),
		a.Authorised, occurred)
	if err != nil {
		return fmt.Errorf("record uninstall attempt: %w", err)
	}
	return nil
}

// ListAttempts returns the tenant's most recent uninstall attempts, newest
// first. deniedOnly narrows to refused attempts, which is the view an analyst
// wants: authorised attempts are routine decommissioning.
func (s *UninstallProtectionStore) ListAttempts(ctx context.Context, tenantID string, deniedOnly bool, limit int) ([]UninstallAttempt, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id::text, COALESCE(agent_id::text, ''), COALESCE(hostname, ''),
		       authorised, occurred_at, created_at
		  FROM uninstall_attempts
		 WHERE tenant_id = $1::uuid
		   AND ($2::boolean = FALSE OR authorised = FALSE)
		 ORDER BY occurred_at DESC
		 LIMIT $3`, tenantID, deniedOnly, limit)
	if err != nil {
		return nil, fmt.Errorf("list uninstall attempts: %w", err)
	}
	defer rows.Close()

	out := make([]UninstallAttempt, 0, limit)
	for rows.Next() {
		var a UninstallAttempt
		if err := rows.Scan(&a.ID, &a.TenantID, &a.AgentID, &a.Hostname,
			&a.Authorised, &a.OccurredAt, &a.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan uninstall attempt: %w", err)
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate uninstall attempts: %w", err)
	}
	return out, nil
}

// nullIfEmpty maps "" to a SQL NULL. The columns it feeds are nullable UUID and
// TEXT; passing "" to a uuid column is a syntax error at the driver, not a
// stored empty string.
func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
