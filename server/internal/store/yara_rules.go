package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// YARARule mirrors the yara_rules table.
type YARARule struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	Content        string   `json:"content"`
	Tags           []string `json:"tags"`
	Enabled        bool     `json:"enabled"`
	Severity       string   `json:"severity"`
	LastMatchCount int      `json:"last_match_count"`
	LastMatchedAt  *string  `json:"last_matched_at,omitempty"`
	CreatedBy      *string  `json:"created_by,omitempty"`
	CreatedAt      string   `json:"created_at"`
	UpdatedAt      string   `json:"updated_at"`
}

// YARAStore handles yara_rules database operations.
type YARAStore struct {
	pool *pgxpool.Pool
}

// NewYARAStore creates a new YARAStore.
func NewYARAStore(pool *pgxpool.Pool) *YARAStore {
	return &YARAStore{pool: pool}
}

const yaraSelectCols = `
	id, name, COALESCE(description, ''),
	content, tags, enabled, severity,
	last_match_count, last_matched_at,
	created_by,
	created_at, updated_at`

func scanYARARule(row pgx.Row) (*YARARule, error) {
	var r YARARule
	var createdAt, updatedAt time.Time
	var lastMatchedAt *time.Time
	var createdBy *string
	err := row.Scan(
		&r.ID, &r.Name, &r.Description,
		&r.Content, &r.Tags, &r.Enabled, &r.Severity,
		&r.LastMatchCount, &lastMatchedAt,
		&createdBy,
		&createdAt, &updatedAt,
	)
	if err != nil {
		return nil, err
	}
	r.CreatedAt = createdAt.Format(time.RFC3339)
	r.UpdatedAt = updatedAt.Format(time.RFC3339)
	if lastMatchedAt != nil {
		s := lastMatchedAt.Format(time.RFC3339)
		r.LastMatchedAt = &s
	}
	r.CreatedBy = createdBy
	if r.Tags == nil {
		r.Tags = []string{}
	}
	return &r, nil
}

// YARAListFilter holds optional filters for listing YARA rules.
type YARAListFilter struct {
	Search   string
	Severity string
	Enabled  *bool
	Limit    int
	Offset   int
}

// List returns YARA rules with optional filtering and pagination.
func (s *YARAStore) List(ctx context.Context, f YARAListFilter) ([]*YARARule, int, error) {
	if f.Limit <= 0 {
		f.Limit = 50
	}
	if f.Limit > 200 {
		f.Limit = 200
	}

	where := "WHERE 1=1"
	args := []interface{}{}
	idx := 1

	if f.Search != "" {
		where += fmt.Sprintf(" AND (name ILIKE $%d OR description ILIKE $%d)", idx, idx+1)
		pattern := "%" + f.Search + "%"
		args = append(args, pattern, pattern)
		idx += 2
	}
	if f.Severity != "" {
		where += fmt.Sprintf(" AND severity = $%d", idx)
		args = append(args, f.Severity)
		idx++
	}
	if f.Enabled != nil {
		where += fmt.Sprintf(" AND enabled = $%d", idx)
		args = append(args, *f.Enabled)
		idx++
	}

	var total int
	err := s.pool.QueryRow(ctx, "SELECT COUNT(*) FROM yara_rules "+where, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("yara_rules count: %w", err)
	}

	args = append(args, f.Limit, f.Offset)
	rows, err := s.pool.Query(ctx, fmt.Sprintf(
		"SELECT %s FROM yara_rules %s ORDER BY enabled DESC, updated_at DESC LIMIT $%d OFFSET $%d",
		yaraSelectCols, where, idx, idx+1,
	), args...)
	if err != nil {
		return nil, 0, fmt.Errorf("yara_rules list: %w", err)
	}
	defer rows.Close()

	var rules []*YARARule
	for rows.Next() {
		r, err := scanYARARule(rows)
		if err != nil {
			continue
		}
		rules = append(rules, r)
	}
	if rules == nil {
		rules = []*YARARule{}
	}
	return rules, total, nil
}

// Get returns a single YARA rule by ID.
func (s *YARAStore) Get(ctx context.Context, id string) (*YARARule, error) {
	row := s.pool.QueryRow(ctx, fmt.Sprintf(
		"SELECT %s FROM yara_rules WHERE id = $1", yaraSelectCols,
	), id)
	r, err := scanYARARule(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("yara rule not found: %s", id)
		}
		return nil, fmt.Errorf("yara_rules get: %w", err)
	}
	return r, nil
}

// UpsertYARARuleInput holds fields for upserting a YARA rule by name (used by GitHub sync).
type UpsertYARARuleInput struct {
	Name        string
	Description string
	Content     string
	Tags        []string
	Enabled     bool
	Severity    string
	Category    string
}

// Upsert inserts a new YARA rule or updates an existing one matched by name.
// Uses ON CONFLICT DO UPDATE for atomic operation (requires yara_rules_name_unique constraint).
// Returns true if a new rule was created, false if an existing rule was updated.
func (s *YARAStore) Upsert(ctx context.Context, in UpsertYARARuleInput) (created bool, err error) {
	if in.Tags == nil {
		in.Tags = []string{}
	}
	if in.Severity == "" {
		in.Severity = "medium"
	}

	// Check existence before upsert to determine created vs updated.
	var existingID string
	_ = s.pool.QueryRow(ctx, `SELECT id FROM yara_rules WHERE name = $1`, in.Name).Scan(&existingID)
	isNew := existingID == ""

	cat := in.Category
	if cat == "" {
		cat = "malware"
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO yara_rules (name, description, content, tags, enabled, severity, category)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (name) DO UPDATE SET
			description = EXCLUDED.description,
			content     = EXCLUDED.content,
			tags        = EXCLUDED.tags,
			severity    = EXCLUDED.severity,
			category    = EXCLUDED.category,
			updated_at  = NOW(),
			enabled     = CASE WHEN EXCLUDED.enabled THEN TRUE ELSE yara_rules.enabled END`,
		in.Name, in.Description, in.Content, in.Tags, in.Enabled, in.Severity, cat,
	)
	if err != nil {
		return false, fmt.Errorf("yara_rules upsert: %w", err)
	}
	return isNew, nil
}

// CreateYARARuleInput holds fields for creating a new YARA rule.
type CreateYARARuleInput struct {
	Name        string
	Description string
	Content     string
	Tags        []string
	Enabled     bool
	Severity    string
	CreatedBy   *string
}

// Create inserts a new YARA rule and returns the created record.
func (s *YARAStore) Create(ctx context.Context, in CreateYARARuleInput) (*YARARule, error) {
	if in.Tags == nil {
		in.Tags = []string{}
	}
	if in.Severity == "" {
		in.Severity = "medium"
	}

	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		INSERT INTO yara_rules (name, description, content, tags, enabled, severity, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING %s`, yaraSelectCols),
		in.Name, in.Description, in.Content, in.Tags, in.Enabled, in.Severity, in.CreatedBy,
	)
	r, err := scanYARARule(row)
	if err != nil {
		return nil, fmt.Errorf("yara_rules create: %w", err)
	}
	return r, nil
}

// UpdateYARARuleInput holds fields for updating a YARA rule.
type UpdateYARARuleInput struct {
	Name        string
	Description string
	Content     string
	Tags        []string
	Enabled     bool
	Severity    string
}

// Update modifies an existing YARA rule and returns the updated record.
func (s *YARAStore) Update(ctx context.Context, id string, in UpdateYARARuleInput) (*YARARule, error) {
	if in.Tags == nil {
		in.Tags = []string{}
	}

	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		UPDATE yara_rules SET
			name        = $2,
			description = $3,
			content     = $4,
			tags        = $5,
			enabled     = $6,
			severity    = $7,
			updated_at  = NOW()
		WHERE id = $1
		RETURNING %s`, yaraSelectCols),
		id, in.Name, in.Description, in.Content, in.Tags, in.Enabled, in.Severity,
	)
	r, err := scanYARARule(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("yara rule not found: %s", id)
		}
		return nil, fmt.Errorf("yara_rules update: %w", err)
	}
	return r, nil
}

// Delete removes a YARA rule by ID.
func (s *YARAStore) Delete(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM yara_rules WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("yara_rules delete: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("yara rule not found: %s", id)
	}
	return nil
}

// Toggle flips the enabled state of a YARA rule.
func (s *YARAStore) Toggle(ctx context.Context, id string) (*YARARule, error) {
	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		UPDATE yara_rules SET enabled = NOT enabled, updated_at = NOW()
		WHERE id = $1
		RETURNING %s`, yaraSelectCols), id)
	r, err := scanYARARule(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("yara rule not found: %s", id)
		}
		return nil, fmt.Errorf("yara_rules toggle: %w", err)
	}
	return r, nil
}

// ListEnabled returns all enabled YARA rules for agent distribution.
// NOTE: Actual YARA scanning on the agent side would require the go-yara library
// (which uses cgo against the YARA C library). This endpoint distributes rule
// content so a future cgo-capable agent build can compile and run them.
func (s *YARAStore) ListEnabled(ctx context.Context) ([]*YARARule, error) {
	rows, err := s.pool.Query(ctx, fmt.Sprintf(
		"SELECT %s FROM yara_rules WHERE enabled = true ORDER BY created_at", yaraSelectCols,
	))
	if err != nil {
		return nil, fmt.Errorf("yara_rules list_enabled: %w", err)
	}
	defer rows.Close()

	var rules []*YARARule
	for rows.Next() {
		r, err := scanYARARule(rows)
		if err != nil {
			continue
		}
		rules = append(rules, r)
	}
	if rules == nil {
		rules = []*YARARule{}
	}
	return rules, nil
}

// RecordMatch increments the match counter and updates last_matched_at.
func (s *YARAStore) RecordMatch(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE yara_rules
		SET last_match_count = last_match_count + 1,
		    last_matched_at  = NOW(),
		    updated_at       = NOW()
		WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("yara_rules record_match: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("yara rule not found: %s", id)
	}
	return nil
}
