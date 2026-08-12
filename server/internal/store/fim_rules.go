package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// FIMRule mirrors a row in the fim_rules table.
type FIMRule struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Path            string   `json:"path"`
	Recursive       bool     `json:"recursive"`
	ExcludePatterns []string `json:"exclude_patterns"`
	Enabled         bool     `json:"enabled"`
	Severity        string   `json:"severity"`
	CreatedAt       string   `json:"created_at"`
}

// FIMRuleStore handles fim_rules database operations.
type FIMRuleStore struct {
	pool *pgxpool.Pool
}

// NewFIMRuleStore creates a new FIMRuleStore backed by the given pool.
func NewFIMRuleStore(pool *pgxpool.Pool) *FIMRuleStore {
	return &FIMRuleStore{pool: pool}
}

const fimSelectCols = `id, name, path, recursive, exclude_patterns, enabled, severity, created_at`

func scanFIMRule(row pgx.Row) (*FIMRule, error) {
	var r FIMRule
	var createdAt time.Time
	err := row.Scan(
		&r.ID, &r.Name, &r.Path, &r.Recursive,
		&r.ExcludePatterns, &r.Enabled, &r.Severity, &createdAt,
	)
	if err != nil {
		return nil, err
	}
	r.CreatedAt = createdAt.Format(time.RFC3339)
	if r.ExcludePatterns == nil {
		r.ExcludePatterns = []string{}
	}
	return &r, nil
}

// FIMRuleFilter holds optional filters for listing FIM rules.
type FIMRuleFilter struct {
	Enabled  *bool
	Severity string
	Limit    int
	Offset   int
}

// List returns FIM rules matching the provided filter with pagination.
func (s *FIMRuleStore) List(ctx context.Context, f FIMRuleFilter) ([]*FIMRule, int, error) {
	if f.Limit <= 0 {
		f.Limit = 100
	}
	if f.Limit > 500 {
		f.Limit = 500
	}

	where := "WHERE 1=1"
	args := []interface{}{}
	idx := 1

	if f.Enabled != nil {
		where += fmt.Sprintf(" AND enabled = $%d", idx)
		args = append(args, *f.Enabled)
		idx++
	}
	if f.Severity != "" {
		where += fmt.Sprintf(" AND severity = $%d", idx)
		args = append(args, f.Severity)
		idx++
	}

	var total int
	err := s.pool.QueryRow(ctx, "SELECT COUNT(*) FROM fim_rules "+where, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("fim_rules count: %w", err)
	}

	args = append(args, f.Limit, f.Offset)
	rows, err := s.pool.Query(ctx, fmt.Sprintf(
		"SELECT %s FROM fim_rules %s ORDER BY created_at ASC LIMIT $%d OFFSET $%d",
		fimSelectCols, where, idx, idx+1,
	), args...)
	if err != nil {
		return nil, 0, fmt.Errorf("fim_rules list: %w", err)
	}
	defer rows.Close()

	var rules []*FIMRule
	for rows.Next() {
		r, err := scanFIMRule(rows)
		if err != nil {
			continue
		}
		rules = append(rules, r)
	}
	if rules == nil {
		rules = []*FIMRule{}
	}
	return rules, total, nil
}

// Get returns a single FIM rule by ID.
func (s *FIMRuleStore) Get(ctx context.Context, id string) (*FIMRule, error) {
	row := s.pool.QueryRow(ctx, fmt.Sprintf(
		"SELECT %s FROM fim_rules WHERE id = $1", fimSelectCols,
	), id)
	r, err := scanFIMRule(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("fim rule not found: %s", id)
		}
		return nil, fmt.Errorf("fim_rules get: %w", err)
	}
	return r, nil
}

// CreateFIMRuleInput holds fields for inserting a new FIM rule.
type CreateFIMRuleInput struct {
	Name            string
	Path            string
	Recursive       bool
	ExcludePatterns []string
	Enabled         bool
	Severity        string
}

// Create inserts a new FIM rule and returns the created record.
func (s *FIMRuleStore) Create(ctx context.Context, in CreateFIMRuleInput) (*FIMRule, error) {
	if in.ExcludePatterns == nil {
		in.ExcludePatterns = []string{}
	}
	if in.Severity == "" {
		in.Severity = "high"
	}

	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		INSERT INTO fim_rules (name, path, recursive, exclude_patterns, enabled, severity)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING %s`, fimSelectCols),
		in.Name, in.Path, in.Recursive, in.ExcludePatterns, in.Enabled, in.Severity,
	)
	r, err := scanFIMRule(row)
	if err != nil {
		return nil, fmt.Errorf("fim_rules create: %w", err)
	}
	return r, nil
}

// UpdateFIMRuleInput holds fields for updating an existing FIM rule.
type UpdateFIMRuleInput struct {
	Name            string
	Path            string
	Recursive       bool
	ExcludePatterns []string
	Enabled         bool
	Severity        string
}

// Update modifies an existing FIM rule and returns the updated record.
func (s *FIMRuleStore) Update(ctx context.Context, id string, in UpdateFIMRuleInput) (*FIMRule, error) {
	if in.ExcludePatterns == nil {
		in.ExcludePatterns = []string{}
	}

	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		UPDATE fim_rules SET
			name             = $2,
			path             = $3,
			recursive        = $4,
			exclude_patterns = $5,
			enabled          = $6,
			severity         = $7
		WHERE id = $1
		RETURNING %s`, fimSelectCols),
		id, in.Name, in.Path, in.Recursive, in.ExcludePatterns, in.Enabled, in.Severity,
	)
	r, err := scanFIMRule(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("fim rule not found: %s", id)
		}
		return nil, fmt.Errorf("fim_rules update: %w", err)
	}
	return r, nil
}

// Delete removes a FIM rule by ID.
func (s *FIMRuleStore) Delete(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM fim_rules WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("fim_rules delete: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("fim rule not found: %s", id)
	}
	return nil
}

// Toggle flips the enabled state of a FIM rule and returns the updated record.
func (s *FIMRuleStore) Toggle(ctx context.Context, id string) (*FIMRule, error) {
	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		UPDATE fim_rules SET enabled = NOT enabled
		WHERE id = $1
		RETURNING %s`, fimSelectCols), id)
	r, err := scanFIMRule(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("fim rule not found: %s", id)
		}
		return nil, fmt.Errorf("fim_rules toggle: %w", err)
	}
	return r, nil
}
