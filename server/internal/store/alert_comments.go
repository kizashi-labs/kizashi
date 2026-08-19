package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// AlertComment represents a user comment on an alert.
type AlertCommentRecord struct {
	ID         string    `json:"id"`
	AlertID    string    `json:"alert_id"`
	AuthorID   string    `json:"author_id"`
	AuthorName string    `json:"author_name"`
	Content    string    `json:"content"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// AlertCommentStore provides CRUD for alert comments.
type AlertCommentStore struct {
	pool *pgxpool.Pool
}

// NewAlertCommentStore creates a new AlertCommentStore.
func NewAlertCommentStore(pool *pgxpool.Pool) *AlertCommentStore {
	return &AlertCommentStore{pool: pool}
}

// List returns all comments for an alert, ordered by creation time ascending.
func (s *AlertCommentStore) List(ctx context.Context, alertID string) ([]AlertCommentRecord, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, alert_id, author_id, author_name, content, created_at, updated_at
		 FROM alert_comments WHERE alert_id=$1 ORDER BY created_at ASC`,
		alertID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []AlertCommentRecord
	for rows.Next() {
		var c AlertCommentRecord
		if err := rows.Scan(&c.ID, &c.AlertID, &c.AuthorID, &c.AuthorName, &c.Content, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		result = append(result, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if result == nil {
		result = []AlertCommentRecord{}
	}
	return result, nil
}

// Add inserts a new comment on an alert.
func (s *AlertCommentStore) Add(ctx context.Context, alertID, authorID, authorName, content string) (AlertCommentRecord, error) {
	var c AlertCommentRecord
	err := s.pool.QueryRow(ctx,
		`INSERT INTO alert_comments (alert_id, author_id, author_name, content)
		 VALUES ($1, $2, $3, $4)
		 RETURNING id, alert_id, author_id, author_name, content, created_at, updated_at`,
		alertID, authorID, authorName, content,
	).Scan(&c.ID, &c.AlertID, &c.AuthorID, &c.AuthorName, &c.Content, &c.CreatedAt, &c.UpdatedAt)
	return c, err
}

// Delete removes a comment by ID. Admins may delete any comment; others only their own.
func (s *AlertCommentStore) Delete(ctx context.Context, commentID, requesterID string, isAdmin bool) error {
	var authorID string
	err := s.pool.QueryRow(ctx,
		`SELECT author_id FROM alert_comments WHERE id=$1`, commentID,
	).Scan(&authorID)
	if err != nil {
		return fmt.Errorf("alert comment not found")
	}
	if !isAdmin && authorID != requesterID {
		return fmt.Errorf("forbidden: not the author")
	}
	_, err = s.pool.Exec(ctx, `DELETE FROM alert_comments WHERE id=$1`, commentID)
	return err
}
