package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// SavedHuntQuery represents a saved threat hunting query with rich metadata.
type SavedHuntQuery struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Description *string    `json:"description,omitempty"`
	Query       string     `json:"query"`
	QueryType   string     `json:"query_type"`
	Tags        []string   `json:"tags"`
	CreatedBy   *string    `json:"created_by,omitempty"`
	IsShared    bool       `json:"is_shared"`
	RunCount    int        `json:"run_count"`
	LastRunAt   *time.Time `json:"last_run_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// SavedHuntStore manages saved_hunt_queries rows.
type SavedHuntStore struct {
	pool *pgxpool.Pool
}

// NewSavedHuntStore creates a SavedHuntStore backed by the given pool.
func NewSavedHuntStore(pool *pgxpool.Pool) *SavedHuntStore {
	return &SavedHuntStore{pool: pool}
}

const huntQueryCols = `id, name, description, query, query_type, tags, created_by::TEXT, is_shared, run_count, last_run_at, created_at, updated_at`

func scanSavedHuntQuery(row interface{ Scan(...any) error }) (SavedHuntQuery, error) {
	var q SavedHuntQuery
	err := row.Scan(
		&q.ID, &q.Name, &q.Description, &q.Query, &q.QueryType, &q.Tags,
		&q.CreatedBy, &q.IsShared, &q.RunCount, &q.LastRunAt, &q.CreatedAt, &q.UpdatedAt,
	)
	return q, err
}

// List returns saved hunt queries visible to the given user.
// If includeShared is true, shared queries from other users are also returned.
func (s *SavedHuntStore) List(ctx context.Context, userID string, includeShared bool) ([]SavedHuntQuery, error) {
	var sql string
	var args []interface{}
	if userID != "" && includeShared {
		sql = `SELECT ` + huntQueryCols + ` FROM saved_hunt_queries WHERE created_by=$1::UUID OR is_shared=true ORDER BY created_at DESC LIMIT 200`
		args = []interface{}{userID}
	} else if userID != "" {
		sql = `SELECT ` + huntQueryCols + ` FROM saved_hunt_queries WHERE created_by=$1::UUID ORDER BY created_at DESC LIMIT 200`
		args = []interface{}{userID}
	} else {
		sql = `SELECT ` + huntQueryCols + ` FROM saved_hunt_queries WHERE is_shared=true ORDER BY created_at DESC LIMIT 200`
	}
	rows, err := s.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []SavedHuntQuery
	for rows.Next() {
		q, err := scanSavedHuntQuery(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, q)
	}
	if result == nil {
		result = []SavedHuntQuery{}
	}
	return result, rows.Err()
}

// Get returns a single saved hunt query by ID.
func (s *SavedHuntStore) Get(ctx context.Context, id string) (SavedHuntQuery, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+huntQueryCols+` FROM saved_hunt_queries WHERE id=$1`, id)
	q, err := scanSavedHuntQuery(row)
	if err != nil {
		return q, fmt.Errorf("saved hunt query not found: %w", err)
	}
	return q, nil
}

// Create inserts a new saved hunt query.
func (s *SavedHuntStore) Create(ctx context.Context, name, description, query, queryType string, tags []string, userID string, isShared bool) (SavedHuntQuery, error) {
	if tags == nil {
		tags = []string{}
	}
	var descPtr *string
	if description != "" {
		descPtr = &description
	}
	var userPtr *string
	if userID != "" {
		userPtr = &userID
	}
	row := s.pool.QueryRow(ctx,
		`INSERT INTO saved_hunt_queries (name, description, query, query_type, tags, created_by, is_shared)
		 VALUES ($1,$2,$3,$4,$5,$6::UUID,$7)
		 RETURNING `+huntQueryCols,
		name, descPtr, query, queryType, tags, userPtr, isShared,
	)
	return scanSavedHuntQuery(row)
}

// Update modifies an existing saved hunt query.
func (s *SavedHuntStore) Update(ctx context.Context, id, name, description, query string, tags []string, isShared bool) (SavedHuntQuery, error) {
	var descPtr *string
	if description != "" {
		descPtr = &description
	}
	if tags == nil {
		tags = []string{}
	}
	row := s.pool.QueryRow(ctx,
		`UPDATE saved_hunt_queries SET name=$1, description=$2, query=$3, tags=$4, is_shared=$5, updated_at=NOW()
		 WHERE id=$6
		 RETURNING `+huntQueryCols,
		name, descPtr, query, tags, isShared, id,
	)
	q, err := scanSavedHuntQuery(row)
	if err != nil {
		return q, fmt.Errorf("saved hunt query not found: %w", err)
	}
	return q, nil
}

// Delete removes a saved hunt query by ID.
func (s *SavedHuntStore) Delete(ctx context.Context, id string) error {
	res, err := s.pool.Exec(ctx, `DELETE FROM saved_hunt_queries WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return fmt.Errorf("saved hunt query not found")
	}
	return nil
}

// IncrementRunCount bumps run_count and sets last_run_at to now for the given query.
func (s *SavedHuntStore) IncrementRunCount(ctx context.Context, id string) {
	_, _ = s.pool.Exec(ctx,
		`UPDATE saved_hunt_queries SET run_count=run_count+1, last_run_at=NOW() WHERE id=$1`, id)
}
