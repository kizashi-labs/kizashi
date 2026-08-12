// Package audit provides structured audit logging with search and export capabilities.
package audit

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Event represents a single audit log entry.
type Event struct {
	ID         string                 `json:"id"`
	Timestamp  time.Time              `json:"timestamp"`
	UserID     string                 `json:"user_id"`
	Username   string                 `json:"username"`
	Action     string                 `json:"action"`
	Resource   string                 `json:"resource"`
	ResourceID string                 `json:"resource_id"`
	OrgID      string                 `json:"org_id"`
	IPAddress  string                 `json:"ip_address"`
	UserAgent  string                 `json:"user_agent"`
	Success    bool                   `json:"success"`
	Details    map[string]interface{} `json:"details,omitempty"`
	RiskScore  int                    `json:"risk_score"`
}

// AuditFilter defines query parameters for searching audit events.
type AuditFilter struct {
	UserID    string
	Action    string
	Resource  string
	StartTime string
	EndTime   string
	OrgID     string
	Limit     int
	Offset    int
}

// AuditStats holds aggregate audit statistics.
type AuditStats struct {
	EventsToday      int            `json:"events_today"`
	Events7d         int            `json:"events_7d"`
	TopUsers         []UserActivity `json:"top_users"`
	SuspiciousEvents int            `json:"suspicious_events"`
}

// UserActivity holds per-user event counts.
type UserActivity struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	Count    int    `json:"count"`
}

// Logger is the structured audit logger.
type Logger struct {
	pool *pgxpool.Pool
	ch   chan *Event
}

// NewLogger creates a new Logger.
func NewLogger(pool *pgxpool.Pool) *Logger {
	return &Logger{
		pool: pool,
		ch:   make(chan *Event, 1000),
	}
}

// Log enqueues an audit event for async persistence. Non-blocking.
func (l *Logger) Log(event *Event) {
	if event == nil {
		return
	}
	event.RiskScore = CalculateRiskScore(event)
	select {
	case l.ch <- event:
	default:
		slog.Warn("audit: channel full, dropping event", "action", event.Action)
	}
}

// Start begins the background goroutine that flushes events to the DB.
func (l *Logger) Start(ctx context.Context) {
	go func() {
		batch := make([]*Event, 0, 50)
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		flush := func() {
			if len(batch) == 0 {
				return
			}
			if err := l.insertBatch(context.Background(), batch); err != nil {
				slog.Warn("audit: batch insert failed", "err", err, "count", len(batch))
			}
			batch = batch[:0]
		}

		for {
			select {
			case <-ctx.Done():
				// Drain remaining
				for {
					select {
					case e := <-l.ch:
						batch = append(batch, e)
					default:
						flush()
						return
					}
				}
			case e := <-l.ch:
				batch = append(batch, e)
				if len(batch) >= 50 {
					flush()
				}
			case <-ticker.C:
				flush()
			}
		}
	}()
}

// insertBatch writes a slice of events to the database in a single statement.
func (l *Logger) insertBatch(ctx context.Context, events []*Event) error {
	if l.pool == nil || len(events) == 0 {
		return nil
	}

	// Build a multi-row INSERT.
	var sb strings.Builder
	sb.WriteString(`INSERT INTO audit_events
		(timestamp, user_id, username, action, resource, resource_id, org_id, ip_address, user_agent, success, details, risk_score)
		VALUES `)

	args := make([]interface{}, 0, len(events)*12)
	for i, e := range events {
		if i > 0 {
			sb.WriteString(", ")
		}
		base := i * 12
		fmt.Fprintf(&sb, "($%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d)",
			base+1, base+2, base+3, base+4, base+5, base+6,
			base+7, base+8, base+9, base+10, base+11, base+12)

		ts := e.Timestamp
		if ts.IsZero() {
			ts = time.Now()
		}
		detailsJSON, _ := json.Marshal(e.Details)
		args = append(args,
			ts, e.UserID, e.Username, e.Action, e.Resource, e.ResourceID,
			e.OrgID, e.IPAddress, e.UserAgent, e.Success, detailsJSON, e.RiskScore,
		)
	}

	_, err := l.pool.Exec(ctx, sb.String(), args...)
	return err
}

// Query returns a paginated list of audit events matching the filter.
func (l *Logger) Query(ctx context.Context, filter AuditFilter) ([]*Event, int, error) {
	if filter.Limit <= 0 {
		filter.Limit = 50
	}
	if filter.Limit > 500 {
		filter.Limit = 500
	}

	conditions := []string{"1=1"}
	args := []interface{}{}
	argIdx := 1

	if filter.UserID != "" {
		conditions = append(conditions, fmt.Sprintf("user_id = $%d", argIdx))
		args = append(args, filter.UserID)
		argIdx++
	}
	if filter.Action != "" {
		conditions = append(conditions, fmt.Sprintf("action = $%d", argIdx))
		args = append(args, filter.Action)
		argIdx++
	}
	if filter.Resource != "" {
		conditions = append(conditions, fmt.Sprintf("resource = $%d", argIdx))
		args = append(args, filter.Resource)
		argIdx++
	}
	if filter.OrgID != "" {
		conditions = append(conditions, fmt.Sprintf("org_id = $%d", argIdx))
		args = append(args, filter.OrgID)
		argIdx++
	}
	if filter.StartTime != "" {
		conditions = append(conditions, fmt.Sprintf("timestamp >= $%d", argIdx))
		args = append(args, filter.StartTime)
		argIdx++
	}
	if filter.EndTime != "" {
		conditions = append(conditions, fmt.Sprintf("timestamp <= $%d", argIdx))
		args = append(args, filter.EndTime)
		argIdx++
	}

	where := strings.Join(conditions, " AND ")

	// Total count
	var total int
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM audit_events WHERE %s", where)
	_ = l.pool.QueryRow(ctx, countQuery, args...).Scan(&total)

	// Paginated rows
	dataQuery := fmt.Sprintf(
		`SELECT id, timestamp, user_id, username, action, resource, resource_id,
		        org_id, ip_address, user_agent, success, details, risk_score
		 FROM audit_events WHERE %s
		 ORDER BY timestamp DESC
		 LIMIT $%d OFFSET $%d`,
		where, argIdx, argIdx+1,
	)
	args = append(args, filter.Limit, filter.Offset)

	rows, err := l.pool.Query(ctx, dataQuery, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var events []*Event
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			slog.Warn("audit: scan event failed", "err", err)
			continue
		}
		events = append(events, e)
	}
	if events == nil {
		events = []*Event{}
	}
	return events, total, nil
}

// ExportCSV returns a CSV-encoded byte slice of matching audit events.
func (l *Logger) ExportCSV(ctx context.Context, filter AuditFilter) ([]byte, error) {
	filter.Limit = 10000
	filter.Offset = 0
	events, _, err := l.Query(ctx, filter)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	_ = w.Write([]string{
		"id", "timestamp", "user_id", "username", "action", "resource",
		"resource_id", "org_id", "ip_address", "success", "risk_score",
	})
	for _, e := range events {
		_ = w.Write([]string{
			e.ID,
			e.Timestamp.Format(time.RFC3339),
			e.UserID,
			e.Username,
			e.Action,
			e.Resource,
			e.ResourceID,
			e.OrgID,
			e.IPAddress,
			fmt.Sprintf("%v", e.Success),
			fmt.Sprintf("%d", e.RiskScore),
		})
	}
	w.Flush()
	return buf.Bytes(), w.Error()
}

// GetStats returns aggregate audit statistics for an organization.
func (l *Logger) GetStats(ctx context.Context, orgID string) (*AuditStats, error) {
	stats := &AuditStats{}

	orgCond := ""
	var args []interface{}
	if orgID != "" {
		orgCond = " AND org_id = $1"
		args = append(args, orgID)
	}

	_ = l.pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM audit_events WHERE timestamp > NOW() - INTERVAL '1 day'"+orgCond,
		args...,
	).Scan(&stats.EventsToday)

	_ = l.pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM audit_events WHERE timestamp > NOW() - INTERVAL '7 days'"+orgCond,
		args...,
	).Scan(&stats.Events7d)

	_ = l.pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM audit_events WHERE risk_score > 50 AND timestamp > NOW() - INTERVAL '7 days'"+orgCond,
		args...,
	).Scan(&stats.SuspiciousEvents)

	// Top users by event count
	rows, err := l.pool.Query(ctx,
		"SELECT user_id, username, COUNT(*) as cnt FROM audit_events WHERE timestamp > NOW() - INTERVAL '7 days'"+
			orgCond+" GROUP BY user_id, username ORDER BY cnt DESC LIMIT 10",
		args...,
	)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var ua UserActivity
			if err := rows.Scan(&ua.UserID, &ua.Username, &ua.Count); err == nil {
				stats.TopUsers = append(stats.TopUsers, ua)
			}
		}
	}
	if stats.TopUsers == nil {
		stats.TopUsers = []UserActivity{}
	}
	return stats, nil
}

// CalculateRiskScore computes a 0-100 risk score for an event.
func CalculateRiskScore(event *Event) int {
	score := 0

	// Unusual hours (before 6am or after 10pm)
	if !event.Timestamp.IsZero() {
		h := event.Timestamp.Hour()
		if h < 6 || h >= 22 {
			score += 20
		}
	}

	action := strings.ToLower(event.Action)

	// Bulk delete
	if strings.Contains(action, "delete") && strings.Contains(action, "bulk") {
		score += 30
	} else if strings.Contains(action, "delete") {
		score += 10
	}

	// Config changes
	if strings.Contains(event.Resource, "config") || strings.Contains(action, "config") {
		score += 15
	}

	// Failed authentication
	if (strings.Contains(action, "login") || strings.Contains(action, "auth")) && !event.Success {
		score += 25
	}

	// Export operations
	if strings.Contains(action, "export") {
		score += 10
	}

	if score > 100 {
		score = 100
	}
	return score
}

type rowScanner interface {
	Scan(dest ...interface{}) error
}

func scanEvent(row rowScanner) (*Event, error) {
	var e Event
	var detailsJSON []byte
	err := row.Scan(
		&e.ID, &e.Timestamp, &e.UserID, &e.Username, &e.Action,
		&e.Resource, &e.ResourceID, &e.OrgID, &e.IPAddress,
		&e.UserAgent, &e.Success, &detailsJSON, &e.RiskScore,
	)
	if err != nil {
		return nil, err
	}
	if len(detailsJSON) > 0 {
		_ = json.Unmarshal(detailsJSON, &e.Details)
	}
	return &e, nil
}
