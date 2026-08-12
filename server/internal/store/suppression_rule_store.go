package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// SuppressionRuleEntry represents an alert suppression rule with pattern matching.
// Named SuppressionRuleEntry to avoid conflicts with existing SuppressionRule type.
type SuppressionRuleEntry struct {
	ID              string     `json:"id"`
	Name            string     `json:"name" binding:"required"`
	Description     string     `json:"description"`
	Pattern         string     `json:"pattern" binding:"required"`
	MatchField      string     `json:"match_field"`
	AgentID         *string    `json:"agent_id,omitempty"`
	SeverityMax     int        `json:"severity_max"`
	Enabled         bool       `json:"enabled"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
	SuppressedCount int        `json:"suppressed_count"`
	CreatedBy       *string    `json:"created_by,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

// SuppressionRuleStore manages alert_suppression_rules persistence.
type SuppressionRuleStore struct {
	pool *pgxpool.Pool
}

// NewSuppressionRuleStore creates a SuppressionRuleStore.
func NewSuppressionRuleStore(pool *pgxpool.Pool) *SuppressionRuleStore {
	return &SuppressionRuleStore{pool: pool}
}

func (s *SuppressionRuleStore) tableExists(ctx context.Context) bool {
	var exists bool
	_ = s.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name='alert_suppression_rules')`).
		Scan(&exists)
	return exists
}

// List returns all suppression rules.
func (s *SuppressionRuleStore) List(ctx context.Context) ([]SuppressionRuleEntry, error) {
	if !s.tableExists(ctx) {
		return []SuppressionRuleEntry{}, nil
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, name, COALESCE(description,''), pattern, COALESCE(match_field,'title'),
		       agent_id::text, severity_max, enabled, expires_at, suppressed_count,
		       created_by::text, created_at, updated_at
		FROM alert_suppression_rules
		ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []SuppressionRuleEntry
	for rows.Next() {
		r := SuppressionRuleEntry{}
		if err := rows.Scan(
			&r.ID, &r.Name, &r.Description, &r.Pattern, &r.MatchField,
			&r.AgentID, &r.SeverityMax, &r.Enabled, &r.ExpiresAt, &r.SuppressedCount,
			&r.CreatedBy, &r.CreatedAt, &r.UpdatedAt,
		); err != nil {
			continue
		}
		rules = append(rules, r)
	}
	if rules == nil {
		rules = []SuppressionRuleEntry{}
	}
	return rules, nil
}

// Get returns a single suppression rule by ID.
func (s *SuppressionRuleStore) Get(ctx context.Context, id string) (*SuppressionRuleEntry, error) {
	if !s.tableExists(ctx) {
		return nil, nil
	}
	r := &SuppressionRuleEntry{}
	err := s.pool.QueryRow(ctx, `
		SELECT id, name, COALESCE(description,''), pattern, COALESCE(match_field,'title'),
		       agent_id::text, severity_max, enabled, expires_at, suppressed_count,
		       created_by::text, created_at, updated_at
		FROM alert_suppression_rules WHERE id = $1`, id,
	).Scan(
		&r.ID, &r.Name, &r.Description, &r.Pattern, &r.MatchField,
		&r.AgentID, &r.SeverityMax, &r.Enabled, &r.ExpiresAt, &r.SuppressedCount,
		&r.CreatedBy, &r.CreatedAt, &r.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return r, nil
}

// Create inserts a new suppression rule and returns it with the generated ID.
func (s *SuppressionRuleStore) Create(ctx context.Context, r SuppressionRuleEntry) (*SuppressionRuleEntry, error) {
	if !s.tableExists(ctx) {
		return nil, nil
	}
	var id string
	err := s.pool.QueryRow(ctx, `
		INSERT INTO alert_suppression_rules
		  (name, description, pattern, match_field, agent_id, severity_max, enabled, expires_at, created_by)
		VALUES ($1, $2, $3, $4, $5::uuid, $6, $7, $8, $9::uuid)
		RETURNING id`,
		r.Name, r.Description, r.Pattern, r.MatchField,
		nilIfEmptyPtr(r.AgentID), r.SeverityMax, r.Enabled, r.ExpiresAt,
		nilIfEmptyPtr(r.CreatedBy),
	).Scan(&id)
	if err != nil {
		return nil, err
	}
	return s.Get(ctx, id)
}

// Update updates an existing suppression rule.
func (s *SuppressionRuleStore) Update(ctx context.Context, id string, r SuppressionRuleEntry) (*SuppressionRuleEntry, error) {
	if !s.tableExists(ctx) {
		return nil, nil
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE alert_suppression_rules
		SET name=$2, description=$3, pattern=$4, match_field=$5,
		    agent_id=$6::uuid, severity_max=$7, enabled=$8, expires_at=$9, updated_at=NOW()
		WHERE id=$1`,
		id, r.Name, r.Description, r.Pattern, r.MatchField,
		nilIfEmptyPtr(r.AgentID), r.SeverityMax, r.Enabled, r.ExpiresAt,
	)
	if err != nil {
		return nil, err
	}
	return s.Get(ctx, id)
}

// Delete removes a suppression rule by ID.
func (s *SuppressionRuleStore) Delete(ctx context.Context, id string) error {
	if !s.tableExists(ctx) {
		return nil
	}
	_, err := s.pool.Exec(ctx, "DELETE FROM alert_suppression_rules WHERE id = $1", id)
	return err
}

// Toggle flips the enabled field of a suppression rule.
func (s *SuppressionRuleStore) Toggle(ctx context.Context, id string) (*SuppressionRuleEntry, error) {
	if !s.tableExists(ctx) {
		return nil, nil
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE alert_suppression_rules SET enabled = NOT enabled, updated_at = NOW() WHERE id = $1`, id)
	if err != nil {
		return nil, err
	}
	return s.Get(ctx, id)
}

// IncrementCount increments the suppressed_count for the given rule.
func (s *SuppressionRuleStore) IncrementCount(ctx context.Context, id string) error {
	if !s.tableExists(ctx) {
		return nil
	}
	_, err := s.pool.Exec(ctx,
		"UPDATE alert_suppression_rules SET suppressed_count = suppressed_count + 1 WHERE id = $1", id)
	return err
}

// nilIfEmptyPtr returns nil if ptr is nil or points to an empty string.
func nilIfEmptyPtr(s *string) interface{} {
	if s == nil || *s == "" {
		return nil
	}
	return *s
}
