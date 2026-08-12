package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AgentPolicy mirrors the agent_policies table.
type AgentPolicy struct {
	ID                  string   `json:"id"`
	Name                string   `json:"name"`
	Description         string   `json:"description"`
	TenantID            string   `json:"tenant_id,omitempty"`
	ScanIntervalMin     int      `json:"scan_interval_min"`
	FullScanHour        int      `json:"full_scan_hour"`
	MonitoredExtensions []string `json:"monitored_extensions"`
	ExcludedPaths       []string `json:"excluded_paths"`
	CPULimitPct         int      `json:"cpu_limit_pct"`
	MemLimitMB          int      `json:"mem_limit_mb"`
	MonitorNetwork      bool     `json:"monitor_network"`
	MonitorDNS          bool     `json:"monitor_dns"`
	LogLevel            string   `json:"log_level"`
	CreatedAt           string   `json:"created_at"`
	UpdatedAt           string   `json:"updated_at"`
}

const defaultPolicyID = "00000000-0000-0000-0000-000000000002"

// AgentPolicyStore handles agent policy database operations.
type AgentPolicyStore struct {
	pool *pgxpool.Pool
}

// NewAgentPolicyStore creates a new AgentPolicyStore.
func NewAgentPolicyStore(pool *pgxpool.Pool) *AgentPolicyStore {
	return &AgentPolicyStore{pool: pool}
}

const policySelectCols = `
	id, name, description,
	COALESCE(tenant_id::text, ''),
	scan_interval_min, full_scan_hour,
	monitored_extensions, excluded_paths,
	cpu_limit_pct, mem_limit_mb,
	monitor_network, monitor_dns,
	log_level,
	created_at, updated_at`

func scanPolicy(row pgx.Row) (*AgentPolicy, error) {
	var p AgentPolicy
	var createdAt, updatedAt time.Time
	err := row.Scan(
		&p.ID, &p.Name, &p.Description, &p.TenantID,
		&p.ScanIntervalMin, &p.FullScanHour,
		&p.MonitoredExtensions, &p.ExcludedPaths,
		&p.CPULimitPct, &p.MemLimitMB,
		&p.MonitorNetwork, &p.MonitorDNS,
		&p.LogLevel,
		&createdAt, &updatedAt,
	)
	if err != nil {
		return nil, err
	}
	p.CreatedAt = createdAt.Format(time.RFC3339)
	p.UpdatedAt = updatedAt.Format(time.RFC3339)
	if p.MonitoredExtensions == nil {
		p.MonitoredExtensions = []string{}
	}
	if p.ExcludedPaths == nil {
		p.ExcludedPaths = []string{}
	}
	return &p, nil
}

// List returns all agent policies ordered by creation time.
func (s *AgentPolicyStore) List(ctx context.Context) ([]*AgentPolicy, error) {
	rows, err := s.pool.Query(ctx, fmt.Sprintf(`
		SELECT %s FROM agent_policies ORDER BY created_at`, policySelectCols))
	if err != nil {
		return nil, fmt.Errorf("agent_policies list: %w", err)
	}
	defer rows.Close()

	var policies []*AgentPolicy
	for rows.Next() {
		p, err := scanPolicy(rows)
		if err != nil {
			continue
		}
		policies = append(policies, p)
	}
	if policies == nil {
		policies = []*AgentPolicy{}
	}
	return policies, nil
}

// Get returns a single policy by ID.
func (s *AgentPolicyStore) Get(ctx context.Context, id string) (*AgentPolicy, error) {
	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		SELECT %s FROM agent_policies WHERE id = $1`, policySelectCols), id)
	p, err := scanPolicy(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("policy not found: %s: %w", id, ErrNotFound)
		}
		return nil, fmt.Errorf("agent_policies get: %w", err)
	}
	return p, nil
}

// CreatePolicyInput holds fields for creating a new policy.
type CreatePolicyInput struct {
	Name                string
	Description         string
	TenantID            string
	ScanIntervalMin     int
	FullScanHour        int
	MonitoredExtensions []string
	ExcludedPaths       []string
	CPULimitPct         int
	MemLimitMB          int
	MonitorNetwork      bool
	MonitorDNS          bool
	LogLevel            string
}

// Create inserts a new agent policy and returns the created record.
func (s *AgentPolicyStore) Create(ctx context.Context, in CreatePolicyInput) (*AgentPolicy, error) {
	if in.MonitoredExtensions == nil {
		in.MonitoredExtensions = []string{".exe", ".dll", ".sh", ".ps1", ".py"}
	}
	if in.ExcludedPaths == nil {
		in.ExcludedPaths = []string{}
	}

	var tenantID *string
	if in.TenantID != "" {
		tenantID = &in.TenantID
	}

	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		INSERT INTO agent_policies (
			name, description, tenant_id,
			scan_interval_min, full_scan_hour,
			monitored_extensions, excluded_paths,
			cpu_limit_pct, mem_limit_mb,
			monitor_network, monitor_dns,
			log_level
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		RETURNING %s`, policySelectCols),
		in.Name, in.Description, tenantID,
		in.ScanIntervalMin, in.FullScanHour,
		in.MonitoredExtensions, in.ExcludedPaths,
		in.CPULimitPct, in.MemLimitMB,
		in.MonitorNetwork, in.MonitorDNS,
		in.LogLevel,
	)
	return scanPolicy(row)
}

// UpdatePolicyInput holds fields for updating an existing policy.
type UpdatePolicyInput struct {
	Name                string
	Description         string
	ScanIntervalMin     int
	FullScanHour        int
	MonitoredExtensions []string
	ExcludedPaths       []string
	CPULimitPct         int
	MemLimitMB          int
	MonitorNetwork      bool
	MonitorDNS          bool
	LogLevel            string
}

// Update modifies an existing policy and returns the updated record.
func (s *AgentPolicyStore) Update(ctx context.Context, id string, in UpdatePolicyInput) (*AgentPolicy, error) {
	if in.MonitoredExtensions == nil {
		in.MonitoredExtensions = []string{}
	}
	if in.ExcludedPaths == nil {
		in.ExcludedPaths = []string{}
	}

	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		UPDATE agent_policies SET
			name                 = $2,
			description          = $3,
			scan_interval_min    = $4,
			full_scan_hour       = $5,
			monitored_extensions = $6,
			excluded_paths       = $7,
			cpu_limit_pct        = $8,
			mem_limit_mb         = $9,
			monitor_network      = $10,
			monitor_dns          = $11,
			log_level            = $12,
			updated_at           = NOW()
		WHERE id = $1
		RETURNING %s`, policySelectCols),
		id,
		in.Name, in.Description,
		in.ScanIntervalMin, in.FullScanHour,
		in.MonitoredExtensions, in.ExcludedPaths,
		in.CPULimitPct, in.MemLimitMB,
		in.MonitorNetwork, in.MonitorDNS,
		in.LogLevel,
	)
	p, err := scanPolicy(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("policy not found: %s: %w", id, ErrNotFound)
		}
		return nil, fmt.Errorf("agent_policies update: %w", err)
	}
	return p, nil
}

// Delete removes a policy by ID. The default policy cannot be deleted.
func (s *AgentPolicyStore) Delete(ctx context.Context, id string) error {
	if id == defaultPolicyID {
		return fmt.Errorf("デフォルトポリシーは削除できません")
	}
	tag, err := s.pool.Exec(ctx, `DELETE FROM agent_policies WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("agent_policies delete: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("policy not found: %s: %w", id, ErrNotFound)
	}
	return nil
}

// GetForGroup returns the policy assigned to a given group (via JOIN).
// If the group has no policy, the default policy is returned.
func (s *AgentPolicyStore) GetForGroup(ctx context.Context, groupID string) (*AgentPolicy, error) {
	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		SELECT %s
		FROM agent_policies ap
		JOIN agent_groups ag ON ag.policy_id = ap.id
		WHERE ag.id = $1`, policySelectCols), groupID)

	p, err := scanPolicy(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// フォールバック: デフォルトポリシーを返す
			return s.Get(ctx, defaultPolicyID)
		}
		return nil, fmt.Errorf("GetForGroup: %w", err)
	}
	return p, nil
}

// AssignToGroup sets the policy_id on an agent_group.
func (s *AgentPolicyStore) AssignToGroup(ctx context.Context, groupID, policyID string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE agent_groups SET policy_id = $2 WHERE id = $1`, groupID, policyID)
	if err != nil {
		return fmt.Errorf("AssignToGroup: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("group not found: %s", groupID)
	}
	return nil
}
