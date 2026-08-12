package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// SuppressionConditions defines the matching criteria for a suppression rule.
type SuppressionConditions struct {
	RuleName       string `json:"rule_name,omitempty"`
	Hostname       string `json:"hostname,omitempty"`
	SeverityMax    int    `json:"severity_max,omitempty"`
	MITRETechnique string `json:"mitre_technique,omitempty"`
	AgentID        string `json:"agent_id,omitempty"`
}

// SuppressionRule represents a rule that suppresses matching alerts.
type SuppressionRule struct {
	ID            string                `json:"id"`
	Name          string                `json:"name"`
	Description   string                `json:"description,omitempty"`
	Conditions    SuppressionConditions `json:"conditions"`
	DurationH     int                   `json:"duration_h"`
	IsActive      bool                  `json:"is_active"`
	HitCount      int                   `json:"hit_count"`
	CreatedBy     *string               `json:"created_by,omitempty"`
	CreatedByName string                `json:"created_by_name,omitempty"`
	ExpiresAt     *time.Time            `json:"expires_at,omitempty"`
	CreatedAt     time.Time             `json:"created_at"`
	UpdatedAt     time.Time             `json:"updated_at"`
}

// SuppressionStore handles suppression rule persistence.
type SuppressionStore struct {
	pool *pgxpool.Pool
}

func NewSuppressionStore(db *DB) *SuppressionStore {
	return &SuppressionStore{pool: db.Pool()}
}

// List returns all suppression rules newest-first.
func (s *SuppressionStore) List(ctx context.Context, activeOnly bool) ([]*SuppressionRule, error) {
	where := ""
	if activeOnly {
		where = "WHERE sr.is_active = TRUE AND (sr.expires_at IS NULL OR sr.expires_at > NOW())"
	}
	rows, err := s.pool.Query(ctx, `
		SELECT sr.id, sr.name, COALESCE(sr.description,''),
		       sr.conditions, sr.duration_h, sr.is_active, sr.hit_count,
		       sr.created_by::text,
		       COALESCE(NULLIF(u.full_name,''), u.email, ''),
		       sr.expires_at, sr.created_at, sr.updated_at
		FROM suppression_rules sr
		LEFT JOIN users u ON u.id = sr.created_by
		`+where+`
		ORDER BY sr.created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []*SuppressionRule
	for rows.Next() {
		r := &SuppressionRule{}
		var condJSON []byte
		var createdBy *string
		if err := rows.Scan(
			&r.ID, &r.Name, &r.Description,
			&condJSON, &r.DurationH, &r.IsActive, &r.HitCount,
			&createdBy, &r.CreatedByName,
			&r.ExpiresAt, &r.CreatedAt, &r.UpdatedAt,
		); err != nil {
			continue
		}
		_ = json.Unmarshal(condJSON, &r.Conditions)
		r.CreatedBy = createdBy
		rules = append(rules, r)
	}
	if rules == nil {
		rules = []*SuppressionRule{}
	}
	return rules, nil
}

// Insert creates a new suppression rule.
func (s *SuppressionStore) Insert(ctx context.Context, r *SuppressionRule) error {
	condJSON, err := json.Marshal(r.Conditions)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO suppression_rules
		  (name, description, conditions, duration_h, is_active, created_by, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6::uuid, $7)`,
		r.Name, r.Description, string(condJSON), r.DurationH,
		r.IsActive, nilIfEmpty(r.CreatedBy), r.ExpiresAt,
	)
	return err
}

// Delete removes a suppression rule.
func (s *SuppressionStore) Delete(ctx context.Context, id string) error {
	result, err := s.pool.Exec(ctx, "DELETE FROM suppression_rules WHERE id = $1", id)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("not found")
	}
	return nil
}

// IncrHitCount atomically increments the hit_count for the given rule.
func (s *SuppressionStore) IncrHitCount(ctx context.Context, id string) {
	_, _ = s.pool.Exec(ctx,
		"UPDATE suppression_rules SET hit_count = hit_count + 1 WHERE id = $1", id,
	)
}

// SetActive toggles a rule's is_active flag.
func (s *SuppressionStore) SetActive(ctx context.Context, id string, active bool) error {
	_, err := s.pool.Exec(ctx,
		"UPDATE suppression_rules SET is_active=$2, updated_at=NOW() WHERE id=$1",
		id, active,
	)
	return err
}
