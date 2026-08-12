package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// AuditLog represents a single admin/mutation action.
type AuditLog struct {
	ID         string                 `json:"id"`
	Timestamp  time.Time              `json:"timestamp"`
	UserID     string                 `json:"user_id"`
	UserEmail  string                 `json:"user_email"`
	Action     string                 `json:"action"`
	ResourceID string                 `json:"resource_id,omitempty"`
	IPAddress  string                 `json:"ip_address,omitempty"`
	StatusCode int                    `json:"status_code"`
	Details    map[string]interface{} `json:"details,omitempty"`
}

// AuditStore handles audit log DB operations.
type AuditStore struct {
	pool *pgxpool.Pool
}

func NewAuditStore(db *DB) *AuditStore {
	return &AuditStore{pool: db.Pool()}
}

// Insert persists an audit log entry (non-blocking; caller may use a goroutine).
func (s *AuditStore) Insert(ctx context.Context, entry *AuditLog) error {
	var detailsVal interface{}
	if entry.Details != nil {
		b, _ := json.Marshal(entry.Details)
		if len(b) > 0 {
			detailsVal = string(b)
		}
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO audit_logs
		       (user_id, user_email, action, resource_id, ip_address, status_code, details)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		entry.UserID,
		entry.UserEmail,
		entry.Action,
		entry.ResourceID,
		entry.IPAddress,
		entry.StatusCode,
		detailsVal,
	)
	return err
}

// AuditFilter holds optional filters for listing audit logs.
type AuditFilter struct {
	UserID     string // exact match on user_id
	UserEmail  string // partial match on user_email
	Action     string // exact match on action (e.g. "login")
	Method     string // HTTP method prefix: GET, POST, PUT, DELETE
	OnlyErrors bool   // only status_code >= 400
}

// List returns audit logs newest-first with pagination and optional filters.
func (s *AuditStore) List(ctx context.Context, limit, offset int, f AuditFilter) ([]*AuditLog, int, error) {
	conds := []string{"1=1"}
	args := []interface{}{}
	idx := 1

	if f.UserID != "" {
		conds = append(conds, fmt.Sprintf("user_id = $%d", idx))
		args = append(args, f.UserID)
		idx++
	}
	if f.UserEmail != "" {
		conds = append(conds, fmt.Sprintf("user_email ILIKE $%d", idx))
		args = append(args, "%"+f.UserEmail+"%")
		idx++
	}
	if f.Action != "" {
		conds = append(conds, fmt.Sprintf("action = $%d", idx))
		args = append(args, f.Action)
		idx++
	}
	if f.Method != "" {
		conds = append(conds, fmt.Sprintf("action ILIKE $%d", idx))
		args = append(args, f.Method+"%")
		idx++
	}
	if f.OnlyErrors {
		conds = append(conds, "status_code >= 400")
	}

	where := "WHERE " + strings.Join(conds, " AND ")

	var total int
	countArgs := make([]interface{}, len(args))
	copy(countArgs, args)
	if err := s.pool.QueryRow(ctx, "SELECT COUNT(*) FROM audit_logs "+where, countArgs...).Scan(&total); err != nil {
		return nil, 0, err
	}

	args = append(args, limit, offset)
	rows, err := s.pool.Query(ctx, fmt.Sprintf(`
		SELECT id, timestamp, COALESCE(user_id,''), COALESCE(user_email,''),
		       action, COALESCE(resource_id,''), COALESCE(ip_address,''),
		       status_code, COALESCE(details,'{}')
		FROM audit_logs
		%s
		ORDER BY timestamp DESC
		LIMIT $%d OFFSET $%d`, where, idx, idx+1),
		args...,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var logs []*AuditLog
	for rows.Next() {
		var l AuditLog
		var detailsJSON string
		if err := rows.Scan(
			&l.ID, &l.Timestamp, &l.UserID, &l.UserEmail,
			&l.Action, &l.ResourceID, &l.IPAddress,
			&l.StatusCode, &detailsJSON,
		); err != nil {
			continue
		}
		_ = json.Unmarshal([]byte(detailsJSON), &l.Details)
		logs = append(logs, &l)
	}
	return logs, total, nil
}
