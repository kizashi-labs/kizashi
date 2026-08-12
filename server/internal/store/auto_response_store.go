package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AutoResponseRule mirrors a row in the auto_response_rules table.
type AutoResponseRule struct {
	ID                 string          `json:"id"`
	Name               string          `json:"name"`
	Description        string          `json:"description"`
	Enabled            bool            `json:"enabled"`
	TriggerSeverityMin int             `json:"trigger_severity_min"`
	TriggerStatus      string          `json:"trigger_status"`
	AlertTitlePattern  string          `json:"alert_title_pattern"`
	ActionType         string          `json:"action_type"`
	ActionParams       json.RawMessage `json:"action_params"`
	CooldownSeconds    int             `json:"cooldown_seconds"`
	ExecutionCount     int             `json:"execution_count"`
	LastExecutedAt     *string         `json:"last_executed_at,omitempty"`
	CreatedAt          string          `json:"created_at"`
	UpdatedAt          string          `json:"updated_at"`
}

// AutoResponseExecution mirrors a row in the auto_response_executions table.
type AutoResponseExecution struct {
	ID          string  `json:"id"`
	RuleID      string  `json:"rule_id"`
	AlertID     string  `json:"alert_id"`
	ActionType  string  `json:"action_type"`
	Status      string  `json:"status"`
	ResultMsg   string  `json:"result_msg"`
	ExecutedAt  string  `json:"executed_at"`
	CompletedAt *string `json:"completed_at,omitempty"`
}

// AutoResponseStore handles auto_response_rules and auto_response_executions operations.
type AutoResponseStore struct {
	pool *pgxpool.Pool
}

// NewAutoResponseStore creates a new AutoResponseStore backed by the given pool.
func NewAutoResponseStore(pool *pgxpool.Pool) *AutoResponseStore {
	return &AutoResponseStore{pool: pool}
}

const autoResponseRuleSelectCols = `id, name, description, enabled, trigger_severity_min, ` +
	`trigger_status, alert_title_pattern, action_type, action_params, cooldown_seconds, ` +
	`execution_count, last_executed_at, created_at, updated_at`

func scanAutoResponseRule(row interface {
	Scan(dest ...interface{}) error
}) (*AutoResponseRule, error) {
	var r AutoResponseRule
	var createdAt, updatedAt time.Time
	var lastExec *time.Time
	var paramRaw []byte
	err := row.Scan(
		&r.ID, &r.Name, &r.Description, &r.Enabled,
		&r.TriggerSeverityMin, &r.TriggerStatus, &r.AlertTitlePattern,
		&r.ActionType, &paramRaw, &r.CooldownSeconds,
		&r.ExecutionCount, &lastExec, &createdAt, &updatedAt,
	)
	if err != nil {
		return nil, err
	}
	r.CreatedAt = createdAt.Format(time.RFC3339)
	r.UpdatedAt = updatedAt.Format(time.RFC3339)
	if lastExec != nil {
		s := lastExec.Format(time.RFC3339)
		r.LastExecutedAt = &s
	}
	if paramRaw != nil {
		r.ActionParams = json.RawMessage(paramRaw)
	} else {
		r.ActionParams = json.RawMessage(`{}`)
	}
	return &r, nil
}

// ListRules returns all auto response rules ordered by created_at.
func (s *AutoResponseStore) ListRules(ctx context.Context) ([]*AutoResponseRule, error) {
	rows, err := s.pool.Query(ctx, fmt.Sprintf(
		`SELECT %s FROM auto_response_rules ORDER BY created_at ASC`,
		autoResponseRuleSelectCols,
	))
	if err != nil {
		return nil, fmt.Errorf("auto_response_rules list: %w", err)
	}
	defer rows.Close()

	var rules []*AutoResponseRule
	for rows.Next() {
		r, err := scanAutoResponseRule(rows)
		if err != nil {
			continue
		}
		rules = append(rules, r)
	}
	if rules == nil {
		rules = []*AutoResponseRule{}
	}
	return rules, nil
}

// GetRule returns a single auto response rule by ID.
func (s *AutoResponseStore) GetRule(ctx context.Context, id string) (*AutoResponseRule, error) {
	row := s.pool.QueryRow(ctx, fmt.Sprintf(
		`SELECT %s FROM auto_response_rules WHERE id = $1`,
		autoResponseRuleSelectCols,
	), id)
	r, err := scanAutoResponseRule(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("auto response rule not found: %s: %w", id, ErrNotFound)
		}
		return nil, fmt.Errorf("auto_response_rules get: %w", err)
	}
	return r, nil
}

// CreateAutoResponseRuleInput holds fields for inserting a new auto response rule.
type CreateAutoResponseRuleInput struct {
	Name               string
	Description        string
	Enabled            bool
	TriggerSeverityMin int
	TriggerStatus      string
	AlertTitlePattern  string
	ActionType         string
	ActionParams       json.RawMessage
	CooldownSeconds    int
}

// CreateRule inserts a new auto response rule and returns the created record.
func (s *AutoResponseStore) CreateRule(ctx context.Context, in CreateAutoResponseRuleInput) (*AutoResponseRule, error) {
	params := in.ActionParams
	if len(params) == 0 {
		params = json.RawMessage(`{}`)
	}
	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		INSERT INTO auto_response_rules
		    (name, description, enabled, trigger_severity_min, trigger_status,
		     alert_title_pattern, action_type, action_params, cooldown_seconds)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING %s`, autoResponseRuleSelectCols),
		in.Name, in.Description, in.Enabled, in.TriggerSeverityMin, in.TriggerStatus,
		in.AlertTitlePattern, in.ActionType, []byte(params), in.CooldownSeconds,
	)
	r, err := scanAutoResponseRule(row)
	if err != nil {
		return nil, fmt.Errorf("auto_response_rules create: %w", err)
	}
	return r, nil
}

// UpdateAutoResponseRuleInput holds fields for updating an existing auto response rule.
type UpdateAutoResponseRuleInput struct {
	Name               string
	Description        string
	Enabled            bool
	TriggerSeverityMin int
	TriggerStatus      string
	AlertTitlePattern  string
	ActionType         string
	ActionParams       json.RawMessage
	CooldownSeconds    int
}

// UpdateRule modifies an existing auto response rule and returns the updated record.
func (s *AutoResponseStore) UpdateRule(ctx context.Context, id string, in UpdateAutoResponseRuleInput) (*AutoResponseRule, error) {
	params := in.ActionParams
	if len(params) == 0 {
		params = json.RawMessage(`{}`)
	}
	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		UPDATE auto_response_rules SET
		    name                = $2,
		    description         = $3,
		    enabled             = $4,
		    trigger_severity_min = $5,
		    trigger_status      = $6,
		    alert_title_pattern = $7,
		    action_type         = $8,
		    action_params       = $9,
		    cooldown_seconds    = $10,
		    updated_at          = NOW()
		WHERE id = $1
		RETURNING %s`, autoResponseRuleSelectCols),
		id, in.Name, in.Description, in.Enabled,
		in.TriggerSeverityMin, in.TriggerStatus, in.AlertTitlePattern,
		in.ActionType, []byte(params), in.CooldownSeconds,
	)
	r, err := scanAutoResponseRule(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("auto response rule not found: %s: %w", id, ErrNotFound)
		}
		return nil, fmt.Errorf("auto_response_rules update: %w", err)
	}
	return r, nil
}

// DeleteRule removes an auto response rule by ID.
func (s *AutoResponseStore) DeleteRule(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM auto_response_rules WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("auto_response_rules delete: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("auto response rule not found: %s: %w", id, ErrNotFound)
	}
	return nil
}

// ToggleRule flips the enabled state of an auto response rule and returns the updated record.
func (s *AutoResponseStore) ToggleRule(ctx context.Context, id string) (*AutoResponseRule, error) {
	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		UPDATE auto_response_rules
		SET enabled = NOT enabled, updated_at = NOW()
		WHERE id = $1
		RETURNING %s`, autoResponseRuleSelectCols), id)
	r, err := scanAutoResponseRule(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("auto response rule not found: %s: %w", id, ErrNotFound)
		}
		return nil, fmt.Errorf("auto_response_rules toggle: %w", err)
	}
	return r, nil
}

// ListEnabled returns all enabled auto response rules.
func (s *AutoResponseStore) ListEnabled(ctx context.Context) ([]*AutoResponseRule, error) {
	rows, err := s.pool.Query(ctx, fmt.Sprintf(
		`SELECT %s FROM auto_response_rules WHERE enabled = true ORDER BY created_at ASC`,
		autoResponseRuleSelectCols,
	))
	if err != nil {
		return nil, fmt.Errorf("auto_response_rules list_enabled: %w", err)
	}
	defer rows.Close()

	var rules []*AutoResponseRule
	for rows.Next() {
		r, err := scanAutoResponseRule(rows)
		if err != nil {
			continue
		}
		rules = append(rules, r)
	}
	if rules == nil {
		rules = []*AutoResponseRule{}
	}
	return rules, nil
}

// ─── Execution helpers ────────────────────────────────────────────────────────

const autoResponseExecutionSelectCols = `id, rule_id::text, alert_id::text, action_type, status, result_msg, executed_at, completed_at`

func scanAutoResponseExecution(row interface {
	Scan(dest ...interface{}) error
}) (*AutoResponseExecution, error) {
	var e AutoResponseExecution
	var executedAt time.Time
	var completedAt *time.Time
	err := row.Scan(
		&e.ID, &e.RuleID, &e.AlertID, &e.ActionType,
		&e.Status, &e.ResultMsg, &executedAt, &completedAt,
	)
	if err != nil {
		return nil, err
	}
	e.ExecutedAt = executedAt.Format(time.RFC3339)
	if completedAt != nil {
		s := completedAt.Format(time.RFC3339)
		e.CompletedAt = &s
	}
	return &e, nil
}

// CreateExecution inserts a new execution record.
func (s *AutoResponseStore) CreateExecution(ctx context.Context, ruleID, alertID, actionType string) (*AutoResponseExecution, error) {
	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		INSERT INTO auto_response_executions (rule_id, alert_id, action_type)
		VALUES ($1, $2, $3)
		RETURNING %s`, autoResponseExecutionSelectCols),
		ruleID, alertID, actionType,
	)
	e, err := scanAutoResponseExecution(row)
	if err != nil {
		return nil, fmt.Errorf("auto_response_executions create: %w", err)
	}
	return e, nil
}

// UpdateExecutionStatus updates the status and optional result message for an execution.
func (s *AutoResponseStore) UpdateExecutionStatus(ctx context.Context, id, status, resultMsg string) error {
	completedClause := ""
	if status == "success" || status == "failed" {
		completedClause = ", completed_at = NOW()"
	}
	q := fmt.Sprintf(`
		UPDATE auto_response_executions
		SET status = $2, result_msg = $3%s
		WHERE id = $1`, completedClause)
	_, err := s.pool.Exec(ctx, q, id, status, resultMsg)
	if err != nil {
		return fmt.Errorf("auto_response_executions update_status: %w", err)
	}
	return nil
}

// ListExecutionsByRule returns the most recent executions for a given rule.
func (s *AutoResponseStore) ListExecutionsByRule(ctx context.Context, ruleID string, limit int) ([]*AutoResponseExecution, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx, fmt.Sprintf(`
		SELECT %s FROM auto_response_executions
		WHERE rule_id = $1
		ORDER BY executed_at DESC
		LIMIT $2`, autoResponseExecutionSelectCols),
		ruleID, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("auto_response_executions list_by_rule: %w", err)
	}
	defer rows.Close()

	var execs []*AutoResponseExecution
	for rows.Next() {
		e, err := scanAutoResponseExecution(rows)
		if err != nil {
			continue
		}
		execs = append(execs, e)
	}
	if execs == nil {
		execs = []*AutoResponseExecution{}
	}
	return execs, nil
}
