package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ResponseAction represents a recorded response action against an agent.
type ResponseAction struct {
	ID          string `json:"id"`
	AgentID     string `json:"agent_id"`
	ActionType  string `json:"action_type"`
	Status      string `json:"status"`
	TriggeredBy string `json:"triggered_by"`
	// TriggeredByName is the resolved user display name (full_name/email) when
	// executed_by is a user UUID. Empty for agent/system actions or unknown
	// users — the UI falls back accordingly.
	TriggeredByName string          `json:"triggered_by_name,omitempty"`
	TriggeredAt     time.Time       `json:"triggered_at"`
	CompletedAt     *time.Time      `json:"completed_at,omitempty"`
	Error           *string         `json:"error,omitempty"`
	Details         json.RawMessage `json:"details,omitempty"`
}

// ResponseActionStore handles persistence of response actions.
type ResponseActionStore struct {
	pool *pgxpool.Pool
}

// NewResponseActionStore creates a new ResponseActionStore.
func NewResponseActionStore(db *DB) *ResponseActionStore {
	return &ResponseActionStore{pool: db.Pool()}
}

// Record inserts a completed response action record.
func (s *ResponseActionStore) Record(ctx context.Context, agentID, actionType, status, triggeredBy string, details interface{}) error {
	var detailsJSON []byte
	if details != nil {
		var err error
		detailsJSON, err = json.Marshal(details)
		if err != nil {
			detailsJSON = nil
		}
	}
	success := status != "failure"

	_, err := s.pool.Exec(ctx, `
		INSERT INTO response_actions
		  (agent_id, action_type, executed_by, success, status_text, details)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, agentID, actionType, triggeredBy, success, status, detailsJSON)
	return err
}

// List returns paginated response actions for an agent, newest first.
func (s *ResponseActionStore) List(ctx context.Context, agentID string, limit, offset int) ([]*ResponseAction, int, error) {
	var total int
	err := s.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM response_actions WHERE agent_id = $1`, agentID,
	).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	// LEFT JOIN users to resolve executed_by (a user UUID) to a display name.
	// executed_by may also be a non-UUID like "agent"/"admin"; the text-cast
	// comparison simply yields no match and triggered_by_name stays empty.
	rows, err := s.pool.Query(ctx, `
		SELECT ra.id, ra.agent_id, ra.action_type,
		       COALESCE(ra.status_text, CASE WHEN ra.success THEN 'success' ELSE 'failure' END),
		       ra.executed_by, ra.executed_at, ra.executed_at, ra.error_msg, ra.details,
		       COALESCE(NULLIF(u.full_name, ''), u.email, '')
		FROM response_actions ra
		LEFT JOIN users u ON u.id::text = ra.executed_by
		WHERE ra.agent_id = $1
		ORDER BY ra.executed_at DESC
		LIMIT $2 OFFSET $3
	`, agentID, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var actions []*ResponseAction
	for rows.Next() {
		a := &ResponseAction{}
		if err := rows.Scan(
			&a.ID, &a.AgentID, &a.ActionType, &a.Status, &a.TriggeredBy,
			&a.TriggeredAt, &a.CompletedAt, &a.Error, &a.Details, &a.TriggeredByName,
		); err != nil {
			continue
		}
		actions = append(actions, a)
	}
	if actions == nil {
		actions = []*ResponseAction{}
	}
	return actions, total, nil
}
