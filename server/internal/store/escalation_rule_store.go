package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// EscalationRule mirrors a row in the alert_escalation_rules table.
type EscalationRule struct {
	ID             string  `json:"id"`
	Name           string  `json:"name"`
	SeverityMin    int16   `json:"severity_min"`
	UnresolvedMins int     `json:"unresolved_mins"`
	EscalateTo     string  `json:"escalate_to"`
	NotifyChannel  *string `json:"notify_channel"`
	Enabled        bool    `json:"enabled"`
	CreatedAt      string  `json:"created_at"`
	UpdatedAt      string  `json:"updated_at"`
}

// EscalationRuleStore handles alert_escalation_rules database operations.
type EscalationRuleStore struct {
	pool *pgxpool.Pool
}

// NewEscalationRuleStore creates a new EscalationRuleStore backed by the given pool.
func NewEscalationRuleStore(pool *pgxpool.Pool) *EscalationRuleStore {
	return &EscalationRuleStore{pool: pool}
}

const escalationSelectCols = `id, name, severity_min, unresolved_mins, escalate_to, notify_channel, enabled, created_at, updated_at`

func scanEscalationRule(row pgx.Row) (*EscalationRule, error) {
	var r EscalationRule
	var createdAt, updatedAt time.Time
	err := row.Scan(
		&r.ID, &r.Name, &r.SeverityMin, &r.UnresolvedMins,
		&r.EscalateTo, &r.NotifyChannel, &r.Enabled,
		&createdAt, &updatedAt,
	)
	if err != nil {
		return nil, err
	}
	r.CreatedAt = createdAt.Format(time.RFC3339)
	r.UpdatedAt = updatedAt.Format(time.RFC3339)
	return &r, nil
}

// List returns all escalation rules ordered by created_at.
func (s *EscalationRuleStore) List(ctx context.Context) ([]*EscalationRule, error) {
	rows, err := s.pool.Query(ctx, fmt.Sprintf(
		"SELECT %s FROM alert_escalation_rules ORDER BY created_at ASC",
		escalationSelectCols,
	))
	if err != nil {
		return nil, fmt.Errorf("escalation_rules list: %w", err)
	}
	defer rows.Close()

	var rules []*EscalationRule
	for rows.Next() {
		r, err := scanEscalationRule(rows)
		if err != nil {
			continue
		}
		rules = append(rules, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if rules == nil {
		rules = []*EscalationRule{}
	}
	return rules, nil
}

// CreateEscalationRuleInput holds fields for inserting a new escalation rule.
type CreateEscalationRuleInput struct {
	Name           string
	SeverityMin    int16
	UnresolvedMins int
	EscalateTo     string
	NotifyChannel  *string
	Enabled        bool
}

// Create inserts a new escalation rule and returns the created record.
func (s *EscalationRuleStore) Create(ctx context.Context, in CreateEscalationRuleInput) (*EscalationRule, error) {
	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		INSERT INTO alert_escalation_rules
		    (name, severity_min, unresolved_mins, escalate_to, notify_channel, enabled)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING %s`, escalationSelectCols),
		in.Name, in.SeverityMin, in.UnresolvedMins, in.EscalateTo, in.NotifyChannel, in.Enabled,
	)
	r, err := scanEscalationRule(row)
	if err != nil {
		return nil, fmt.Errorf("escalation_rules create: %w", err)
	}
	return r, nil
}

// UpdateEscalationRuleInput holds fields for updating an existing escalation rule.
type UpdateEscalationRuleInput struct {
	Name           string
	SeverityMin    int16
	UnresolvedMins int
	EscalateTo     string
	NotifyChannel  *string
	Enabled        bool
}

// Update modifies an existing escalation rule and returns the updated record.
func (s *EscalationRuleStore) Update(ctx context.Context, id string, in UpdateEscalationRuleInput) (*EscalationRule, error) {
	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		UPDATE alert_escalation_rules SET
		    name            = $2,
		    severity_min    = $3,
		    unresolved_mins = $4,
		    escalate_to     = $5,
		    notify_channel  = $6,
		    enabled         = $7,
		    updated_at      = NOW()
		WHERE id = $1
		RETURNING %s`, escalationSelectCols),
		id, in.Name, in.SeverityMin, in.UnresolvedMins, in.EscalateTo, in.NotifyChannel, in.Enabled,
	)
	r, err := scanEscalationRule(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("escalation rule not found: %s", id)
		}
		return nil, fmt.Errorf("escalation_rules update: %w", err)
	}
	return r, nil
}

// Delete removes an escalation rule by ID.
func (s *EscalationRuleStore) Delete(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM alert_escalation_rules WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("escalation_rules delete: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("escalation rule not found: %s", id)
	}
	return nil
}

// Toggle flips the enabled state of an escalation rule and returns the updated record.
func (s *EscalationRuleStore) Toggle(ctx context.Context, id string) (*EscalationRule, error) {
	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		UPDATE alert_escalation_rules
		SET enabled = NOT enabled, updated_at = NOW()
		WHERE id = $1
		RETURNING %s`, escalationSelectCols), id)
	r, err := scanEscalationRule(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("escalation rule not found: %s", id)
		}
		return nil, fmt.Errorf("escalation_rules toggle: %w", err)
	}
	return r, nil
}

// ListEnabledForSeverity returns enabled rules where severity_min <= severityMin.
func (s *EscalationRuleStore) ListEnabledForSeverity(ctx context.Context, severityMin int) ([]*EscalationRule, error) {
	rows, err := s.pool.Query(ctx, fmt.Sprintf(`
		SELECT %s FROM alert_escalation_rules
		WHERE enabled = true AND severity_min <= $1
		ORDER BY severity_min DESC, created_at ASC`,
		escalationSelectCols),
		severityMin,
	)
	if err != nil {
		return nil, fmt.Errorf("escalation_rules list_enabled: %w", err)
	}
	defer rows.Close()

	var rules []*EscalationRule
	for rows.Next() {
		r, err := scanEscalationRule(rows)
		if err != nil {
			continue
		}
		rules = append(rules, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if rules == nil {
		rules = []*EscalationRule{}
	}
	return rules, nil
}
