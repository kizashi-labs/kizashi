package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ProcessBlockRule mirrors the process_block_rules table.
type ProcessBlockRule struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	ProcessName string  `json:"process_name"`
	RuleType    string  `json:"rule_type"`
	Scope       string  `json:"scope"`
	ScopeID     *string `json:"scope_id,omitempty"`
	Action      string  `json:"action"`
	Enabled     bool    `json:"enabled"`
	Severity    string  `json:"severity"`
	CreatedAt   string  `json:"created_at"`
}

// ProcessBlockRuleStore handles process_block_rules database operations.
type ProcessBlockRuleStore struct {
	pool *pgxpool.Pool
}

// NewProcessBlockRuleStore creates a new ProcessBlockRuleStore.
func NewProcessBlockRuleStore(pool *pgxpool.Pool) *ProcessBlockRuleStore {
	return &ProcessBlockRuleStore{pool: pool}
}

const processBlockSelectCols = `
	id, name, process_name, rule_type, scope, scope_id,
	action, enabled, severity, created_at`

func scanProcessBlockRule(row pgx.Row) (*ProcessBlockRule, error) {
	var r ProcessBlockRule
	var createdAt time.Time
	err := row.Scan(
		&r.ID, &r.Name, &r.ProcessName, &r.RuleType, &r.Scope, &r.ScopeID,
		&r.Action, &r.Enabled, &r.Severity, &createdAt,
	)
	if err != nil {
		return nil, err
	}
	r.CreatedAt = createdAt.Format(time.RFC3339)
	return &r, nil
}

// ProcessBlockRuleFilter holds optional filters for listing rules.
type ProcessBlockRuleFilter struct {
	RuleType string
	Scope    string
	Enabled  *bool
	Limit    int
	Offset   int
}

// List returns process block rules with optional filtering and pagination.
func (s *ProcessBlockRuleStore) List(ctx context.Context, f ProcessBlockRuleFilter) ([]*ProcessBlockRule, int, error) {
	if f.Limit <= 0 {
		f.Limit = 100
	}
	if f.Limit > 500 {
		f.Limit = 500
	}

	where := "WHERE 1=1"
	args := []interface{}{}
	idx := 1

	if f.RuleType != "" {
		where += fmt.Sprintf(" AND rule_type = $%d", idx)
		args = append(args, f.RuleType)
		idx++
	}
	if f.Scope != "" {
		where += fmt.Sprintf(" AND scope = $%d", idx)
		args = append(args, f.Scope)
		idx++
	}
	if f.Enabled != nil {
		where += fmt.Sprintf(" AND enabled = $%d", idx)
		args = append(args, *f.Enabled)
		idx++
	}

	var total int
	err := s.pool.QueryRow(ctx, "SELECT COUNT(*) FROM process_block_rules "+where, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("process_block_rules count: %w", err)
	}

	args = append(args, f.Limit, f.Offset)
	rows, err := s.pool.Query(ctx, fmt.Sprintf(
		"SELECT %s FROM process_block_rules %s ORDER BY created_at DESC LIMIT $%d OFFSET $%d",
		processBlockSelectCols, where, idx, idx+1,
	), args...)
	if err != nil {
		return nil, 0, fmt.Errorf("process_block_rules list: %w", err)
	}
	defer rows.Close()

	var rules []*ProcessBlockRule
	for rows.Next() {
		r, err := scanProcessBlockRule(rows)
		if err != nil {
			continue
		}
		rules = append(rules, r)
	}
	if rules == nil {
		rules = []*ProcessBlockRule{}
	}
	return rules, total, nil
}

// Get returns a single process block rule by ID.
func (s *ProcessBlockRuleStore) Get(ctx context.Context, id string) (*ProcessBlockRule, error) {
	row := s.pool.QueryRow(ctx, fmt.Sprintf(
		"SELECT %s FROM process_block_rules WHERE id = $1", processBlockSelectCols,
	), id)
	r, err := scanProcessBlockRule(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("process block rule not found: %s", id)
		}
		return nil, fmt.Errorf("process_block_rules get: %w", err)
	}
	return r, nil
}

// CreateProcessBlockRuleInput holds fields for creating a new rule.
type CreateProcessBlockRuleInput struct {
	Name        string
	ProcessName string
	RuleType    string
	Scope       string
	ScopeID     *string
	Action      string
	Enabled     bool
	Severity    string
}

// Create inserts a new process block rule and returns the created record.
func (s *ProcessBlockRuleStore) Create(ctx context.Context, in CreateProcessBlockRuleInput) (*ProcessBlockRule, error) {
	if in.RuleType == "" {
		in.RuleType = "deny"
	}
	if in.Scope == "" {
		in.Scope = "all"
	}
	if in.Action == "" {
		in.Action = "alert"
	}
	if in.Severity == "" {
		in.Severity = "high"
	}

	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		INSERT INTO process_block_rules
			(name, process_name, rule_type, scope, scope_id, action, enabled, severity)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING %s`, processBlockSelectCols),
		in.Name, in.ProcessName, in.RuleType, in.Scope, in.ScopeID,
		in.Action, in.Enabled, in.Severity,
	)
	r, err := scanProcessBlockRule(row)
	if err != nil {
		return nil, fmt.Errorf("process_block_rules create: %w", err)
	}
	return r, nil
}

// UpdateProcessBlockRuleInput holds fields for updating a rule.
type UpdateProcessBlockRuleInput struct {
	Name        string
	ProcessName string
	RuleType    string
	Scope       string
	ScopeID     *string
	Action      string
	Enabled     bool
	Severity    string
}

// Update modifies an existing process block rule and returns the updated record.
func (s *ProcessBlockRuleStore) Update(ctx context.Context, id string, in UpdateProcessBlockRuleInput) (*ProcessBlockRule, error) {
	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		UPDATE process_block_rules SET
			name         = $2,
			process_name = $3,
			rule_type    = $4,
			scope        = $5,
			scope_id     = $6,
			action       = $7,
			enabled      = $8,
			severity     = $9
		WHERE id = $1
		RETURNING %s`, processBlockSelectCols),
		id, in.Name, in.ProcessName, in.RuleType, in.Scope, in.ScopeID,
		in.Action, in.Enabled, in.Severity,
	)
	r, err := scanProcessBlockRule(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("process block rule not found: %s", id)
		}
		return nil, fmt.Errorf("process_block_rules update: %w", err)
	}
	return r, nil
}

// Delete removes a process block rule by ID.
func (s *ProcessBlockRuleStore) Delete(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM process_block_rules WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("process_block_rules delete: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("process block rule not found: %s", id)
	}
	return nil
}

// Toggle flips the enabled state of a process block rule.
func (s *ProcessBlockRuleStore) Toggle(ctx context.Context, id string) (*ProcessBlockRule, error) {
	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		UPDATE process_block_rules SET enabled = NOT enabled
		WHERE id = $1
		RETURNING %s`, processBlockSelectCols), id)
	r, err := scanProcessBlockRule(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("process block rule not found: %s", id)
		}
		return nil, fmt.Errorf("process_block_rules toggle: %w", err)
	}
	return r, nil
}

// ListForAgent returns enabled rules applicable to a given agent, combining:
//   - rules with scope='all'
//   - rules with scope='agent' and scope_id = agentID
//
// Note: group-scoped rules (scope='group') require the caller to resolve which
// group the agent belongs to and call ListForScope additionally. This method
// covers the most common cases efficiently.
func (s *ProcessBlockRuleStore) ListForAgent(ctx context.Context, agentID string) ([]*ProcessBlockRule, error) {
	rows, err := s.pool.Query(ctx, fmt.Sprintf(`
		SELECT %s FROM process_block_rules
		WHERE enabled = true
		  AND (
		    scope = 'all'
		    OR (scope = 'agent' AND scope_id = $1)
		  )
		ORDER BY created_at`, processBlockSelectCols), agentID)
	if err != nil {
		return nil, fmt.Errorf("process_block_rules list_for_agent: %w", err)
	}
	defer rows.Close()

	var rules []*ProcessBlockRule
	for rows.Next() {
		r, err := scanProcessBlockRule(rows)
		if err != nil {
			continue
		}
		rules = append(rules, r)
	}
	if rules == nil {
		rules = []*ProcessBlockRule{}
	}
	return rules, nil
}
