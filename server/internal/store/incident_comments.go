package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// IncidentComment represents a user comment on an incident.
type IncidentComment struct {
	ID         string    `json:"id"`
	IncidentID string    `json:"incident_id"`
	UserID     string    `json:"user_id"`
	UserName   string    `json:"user_name,omitempty"`
	Body       string    `json:"body"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// IncidentCommentStore provides CRUD for incident comments.
type IncidentCommentStore struct {
	pool *pgxpool.Pool
}

// NewIncidentCommentStore creates a new IncidentCommentStore.
func NewIncidentCommentStore(pool *pgxpool.Pool) *IncidentCommentStore {
	return &IncidentCommentStore{pool: pool}
}

// List returns all comments for an incident, newest first.
func (s *IncidentCommentStore) List(ctx context.Context, incidentID string) ([]IncidentComment, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT c.id, c.incident_id::text, c.user_id::text,
		       COALESCE(NULLIF(u.full_name,''), u.email, ''),
		       c.body, c.created_at, c.updated_at
		FROM incident_comments c
		LEFT JOIN users u ON u.id = c.user_id
		WHERE c.incident_id = $1
		ORDER BY c.created_at DESC`, incidentID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var comments []IncidentComment
	for rows.Next() {
		var c IncidentComment
		if err := rows.Scan(
			&c.ID, &c.IncidentID, &c.UserID, &c.UserName,
			&c.Body, &c.CreatedAt, &c.UpdatedAt,
		); err != nil {
			continue
		}
		comments = append(comments, c)
	}
	if comments == nil {
		comments = []IncidentComment{}
	}
	return comments, nil
}

// Add inserts a new comment on an incident.
func (s *IncidentCommentStore) Add(ctx context.Context, incidentID, userID, body string) (IncidentComment, error) {
	var c IncidentComment
	err := s.pool.QueryRow(ctx, `
		INSERT INTO incident_comments (incident_id, user_id, body)
		VALUES ($1::uuid, $2::uuid, $3)
		RETURNING id, incident_id::text, user_id::text, body, created_at, updated_at`,
		incidentID, userID, body,
	).Scan(&c.ID, &c.IncidentID, &c.UserID, &c.Body, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return IncidentComment{}, err
	}
	return c, nil
}

// Delete removes a comment by ID. Only the owning user may delete their comment.
func (s *IncidentCommentStore) Delete(ctx context.Context, id, userID string) error {
	result, err := s.pool.Exec(ctx,
		"DELETE FROM incident_comments WHERE id = $1::uuid AND user_id = $2::uuid",
		id, userID,
	)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("comment not found or not owned by user")
	}
	return nil
}
