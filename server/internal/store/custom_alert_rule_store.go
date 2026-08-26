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

// Condition represents a single match condition in a custom alert rule.
type Condition struct {
	Field    string `json:"field"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
}

// CustomAlertRule mirrors a row in the custom_alert_rules table.
type CustomAlertRule struct {
	ID                string          `json:"id"`
	Name              string          `json:"name"`
	Description       string          `json:"description"`
	Enabled           bool            `json:"enabled"`
	EventType         string          `json:"event_type"`
	Conditions        json.RawMessage `json:"conditions"`
	ThresholdCount    int             `json:"threshold_count"`
	TimeWindowSeconds int             `json:"time_window_seconds"`
	Severity          int             `json:"severity"`
	AlertTitle        string          `json:"alert_title"`
	AlertDescription  string          `json:"alert_description"`
	MitreTags         []string        `json:"mitre_tags"`
	CreatedBy         *string         `json:"created_by,omitempty"`
	CreatedAt         string          `json:"created_at"`
	UpdatedAt         string          `json:"updated_at"`
}

// CustomAlertRuleStore handles custom_alert_rules database operations.
type CustomAlertRuleStore struct {
	pool *pgxpool.Pool
}

// NewCustomAlertRuleStore creates a new CustomAlertRuleStore backed by the given pool.
func NewCustomAlertRuleStore(pool *pgxpool.Pool) *CustomAlertRuleStore {
	return &CustomAlertRuleStore{pool: pool}
}

const customAlertRuleSelectCols = `id, name, description, enabled, event_type, conditions, ` +
	`threshold_count, time_window_seconds, severity, alert_title, alert_description, ` +
	`mitre_tags, created_by::text, created_at, updated_at`

func scanCustomAlertRule(row interface {
	Scan(dest ...interface{}) error
}) (*CustomAlertRule, error) {
	var r CustomAlertRule
	var createdAt, updatedAt time.Time
	var condRaw []byte
	var mitreTags []string
	err := row.Scan(
		&r.ID, &r.Name, &r.Description, &r.Enabled, &r.EventType,
		&condRaw, &r.ThresholdCount, &r.TimeWindowSeconds, &r.Severity,
		&r.AlertTitle, &r.AlertDescription, &mitreTags,
		&r.CreatedBy, &createdAt, &updatedAt,
	)
	if err != nil {
		return nil, err
	}
	r.CreatedAt = createdAt.Format(time.RFC3339)
	r.UpdatedAt = updatedAt.Format(time.RFC3339)
	if condRaw != nil {
		r.Conditions = json.RawMessage(condRaw)
	} else {
		r.Conditions = json.RawMessage(`[]`)
	}
	if mitreTags != nil {
		r.MitreTags = mitreTags
	} else {
		r.MitreTags = []string{}
	}
	return &r, nil
}

// List returns all custom alert rules ordered by created_at.
func (s *CustomAlertRuleStore) List(ctx context.Context) ([]*CustomAlertRule, error) {
	rows, err := s.pool.Query(ctx, fmt.Sprintf(
		`SELECT %s FROM custom_alert_rules ORDER BY created_at ASC`,
		customAlertRuleSelectCols,
	))
	if err != nil {
		return nil, fmt.Errorf("custom_alert_rules list: %w", err)
	}
	defer rows.Close()

	var rules []*CustomAlertRule
	for rows.Next() {
		r, err := scanCustomAlertRule(rows)
		if err != nil {
			continue
		}
		rules = append(rules, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if rules == nil {
		rules = []*CustomAlertRule{}
	}
	return rules, nil
}

// CreateCustomAlertRuleInput holds fields for inserting a new custom alert rule.
type CreateCustomAlertRuleInput struct {
	Name              string
	Description       string
	Enabled           bool
	EventType         string
	Conditions        json.RawMessage
	ThresholdCount    int
	TimeWindowSeconds int
	Severity          int
	AlertTitle        string
	AlertDescription  string
	MitreTags         []string
	CreatedBy         *string
}

// Create inserts a new custom alert rule and returns the created record.
func (s *CustomAlertRuleStore) Create(ctx context.Context, in CreateCustomAlertRuleInput) (*CustomAlertRule, error) {
	cond := in.Conditions
	if len(cond) == 0 {
		cond = json.RawMessage(`[]`)
	}
	tags := in.MitreTags
	if tags == nil {
		tags = []string{}
	}
	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		INSERT INTO custom_alert_rules
		    (name, description, enabled, event_type, conditions,
		     threshold_count, time_window_seconds, severity,
		     alert_title, alert_description, mitre_tags, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		RETURNING %s`, customAlertRuleSelectCols),
		in.Name, in.Description, in.Enabled, in.EventType, []byte(cond),
		in.ThresholdCount, in.TimeWindowSeconds, in.Severity,
		in.AlertTitle, in.AlertDescription, tags, in.CreatedBy,
	)
	r, err := scanCustomAlertRule(row)
	if err != nil {
		return nil, fmt.Errorf("custom_alert_rules create: %w", err)
	}
	return r, nil
}

// Get returns a single custom alert rule by ID.
func (s *CustomAlertRuleStore) Get(ctx context.Context, id string) (*CustomAlertRule, error) {
	row := s.pool.QueryRow(ctx, fmt.Sprintf(
		`SELECT %s FROM custom_alert_rules WHERE id = $1`,
		customAlertRuleSelectCols,
	), id)
	r, err := scanCustomAlertRule(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("custom alert rule not found: %s: %w", id, ErrNotFound)
		}
		return nil, fmt.Errorf("custom_alert_rules get: %w", err)
	}
	return r, nil
}

// UpdateCustomAlertRuleInput holds fields for updating an existing custom alert rule.
type UpdateCustomAlertRuleInput struct {
	Name              string
	Description       string
	Enabled           bool
	EventType         string
	Conditions        json.RawMessage
	ThresholdCount    int
	TimeWindowSeconds int
	Severity          int
	AlertTitle        string
	AlertDescription  string
	MitreTags         []string
}

// Update modifies an existing custom alert rule and returns the updated record.
func (s *CustomAlertRuleStore) Update(ctx context.Context, id string, in UpdateCustomAlertRuleInput) (*CustomAlertRule, error) {
	cond := in.Conditions
	if len(cond) == 0 {
		cond = json.RawMessage(`[]`)
	}
	tags := in.MitreTags
	if tags == nil {
		tags = []string{}
	}
	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		UPDATE custom_alert_rules SET
		    name               = $2,
		    description        = $3,
		    enabled            = $4,
		    event_type         = $5,
		    conditions         = $6,
		    threshold_count    = $7,
		    time_window_seconds = $8,
		    severity           = $9,
		    alert_title        = $10,
		    alert_description  = $11,
		    mitre_tags         = $12,
		    updated_at         = NOW()
		WHERE id = $1
		RETURNING %s`, customAlertRuleSelectCols),
		id, in.Name, in.Description, in.Enabled, in.EventType, []byte(cond),
		in.ThresholdCount, in.TimeWindowSeconds, in.Severity,
		in.AlertTitle, in.AlertDescription, tags,
	)
	r, err := scanCustomAlertRule(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("custom alert rule not found: %s: %w", id, ErrNotFound)
		}
		return nil, fmt.Errorf("custom_alert_rules update: %w", err)
	}
	return r, nil
}

// Delete removes a custom alert rule by ID.
func (s *CustomAlertRuleStore) Delete(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM custom_alert_rules WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("custom_alert_rules delete: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("custom alert rule not found: %s: %w", id, ErrNotFound)
	}
	return nil
}

// Toggle flips the enabled state of a custom alert rule and returns the updated record.
func (s *CustomAlertRuleStore) Toggle(ctx context.Context, id string) (*CustomAlertRule, error) {
	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		UPDATE custom_alert_rules
		SET enabled = NOT enabled, updated_at = NOW()
		WHERE id = $1
		RETURNING %s`, customAlertRuleSelectCols), id)
	r, err := scanCustomAlertRule(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("custom alert rule not found: %s: %w", id, ErrNotFound)
		}
		return nil, fmt.Errorf("custom_alert_rules toggle: %w", err)
	}
	return r, nil
}

// ListEnabled returns all enabled custom alert rules.
func (s *CustomAlertRuleStore) ListEnabled(ctx context.Context) ([]*CustomAlertRule, error) {
	rows, err := s.pool.Query(ctx, fmt.Sprintf(
		`SELECT %s FROM custom_alert_rules WHERE enabled = true ORDER BY created_at ASC`,
		customAlertRuleSelectCols,
	))
	if err != nil {
		return nil, fmt.Errorf("custom_alert_rules list_enabled: %w", err)
	}
	defer rows.Close()

	var rules []*CustomAlertRule
	for rows.Next() {
		r, err := scanCustomAlertRule(rows)
		if err != nil {
			continue
		}
		rules = append(rules, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if rules == nil {
		rules = []*CustomAlertRule{}
	}
	return rules, nil
}
