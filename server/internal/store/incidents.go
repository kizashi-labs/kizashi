package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Incident groups related alerts into a tracked security incident.
type Incident struct {
	ID             string     `json:"id"`
	Title          string     `json:"title"`
	Description    string     `json:"description,omitempty"`
	Severity       int        `json:"severity"`
	Status         string     `json:"status"`
	AssignedTo     *string    `json:"assigned_to,omitempty"`
	AssignedToName string     `json:"assigned_to_name,omitempty"`
	CreatedBy      *string    `json:"created_by,omitempty"`
	CreatedByName  string     `json:"created_by_name,omitempty"`
	AlertCount     int        `json:"alert_count"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	ResolvedAt     *time.Time `json:"resolved_at,omitempty"`
}

// IncidentAlert is an alert linked to an incident.
type IncidentAlert struct {
	AlertID        string    `json:"alert_id"`
	Title          string    `json:"title"`
	Severity       int       `json:"severity"`
	Status         string    `json:"status"`
	Hostname       string    `json:"hostname"`
	MITRETechnique string    `json:"mitre_technique"`
	CreatedAt      time.Time `json:"created_at"`
	LinkedAt       time.Time `json:"linked_at"`
}

// IncidentStore manages incident persistence.
type IncidentStore struct {
	pool *pgxpool.Pool
}

func NewIncidentStore(db *DB) *IncidentStore {
	return &IncidentStore{pool: db.Pool()}
}

// Pool returns the underlying connection pool.
func (s *IncidentStore) Pool() *pgxpool.Pool {
	return s.pool
}

// List returns incidents with alert counts, newest first.
func (s *IncidentStore) List(ctx context.Context, status string, limit, offset int) ([]*Incident, int, error) {
	where := "WHERE 1=1"
	args := []interface{}{}
	argIdx := 1
	if status == "active" {
		// "active" = 対応が必要なステータス（解決済み・クローズ済みを除く）
		where += " AND i.status IN ('open','investigating','contained')"
	} else if status != "" {
		where += fmt.Sprintf(" AND i.status = $%d", argIdx)
		args = append(args, status)
		argIdx++
	}

	var total int
	countArgs := make([]interface{}, len(args))
	copy(countArgs, args)
	_ = s.pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM incidents i "+where, countArgs...,
	).Scan(&total)

	args = append(args, limit, offset)
	rows, err := s.pool.Query(ctx, `
		SELECT i.id, i.title, COALESCE(i.description,''),
		       i.severity, i.status,
		       i.assigned_to::text,
		       COALESCE(NULLIF(ua.full_name,''), ua.email, ''),
		       i.created_by::text,
		       COALESCE(NULLIF(uc.full_name,''), uc.email, ''),
		       COUNT(ia.alert_id) AS alert_count,
		       i.created_at, i.updated_at, i.resolved_at
		FROM incidents i
		LEFT JOIN users ua ON ua.id = i.assigned_to
		LEFT JOIN users uc ON uc.id = i.created_by
		LEFT JOIN incident_alerts ia ON ia.incident_id = i.id
		`+where+fmt.Sprintf(`
		GROUP BY i.id, ua.full_name, ua.email, uc.full_name, uc.email
		ORDER BY i.created_at DESC
		LIMIT $%d OFFSET $%d`, argIdx, argIdx+1),
		args...,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var incidents []*Incident
	for rows.Next() {
		inc := &Incident{}
		var assignedTo, createdBy *string
		if err := rows.Scan(
			&inc.ID, &inc.Title, &inc.Description,
			&inc.Severity, &inc.Status,
			&assignedTo, &inc.AssignedToName,
			&createdBy, &inc.CreatedByName,
			&inc.AlertCount,
			&inc.CreatedAt, &inc.UpdatedAt, &inc.ResolvedAt,
		); err != nil {
			continue
		}
		inc.AssignedTo = assignedTo
		inc.CreatedBy = createdBy
		incidents = append(incidents, inc)
	}
	if incidents == nil {
		incidents = []*Incident{}
	}
	return incidents, total, nil
}

// Get retrieves a single incident.
func (s *IncidentStore) Get(ctx context.Context, id string) (*Incident, error) {
	inc := &Incident{}
	var assignedTo, createdBy *string
	err := s.pool.QueryRow(ctx, `
		SELECT i.id, i.title, COALESCE(i.description,''),
		       i.severity, i.status,
		       i.assigned_to::text,
		       COALESCE(NULLIF(ua.full_name,''), ua.email, ''),
		       i.created_by::text,
		       COALESCE(NULLIF(uc.full_name,''), uc.email, ''),
		       COUNT(ia.alert_id),
		       i.created_at, i.updated_at, i.resolved_at
		FROM incidents i
		LEFT JOIN users ua ON ua.id = i.assigned_to
		LEFT JOIN users uc ON uc.id = i.created_by
		LEFT JOIN incident_alerts ia ON ia.incident_id = i.id
		WHERE i.id = $1
		GROUP BY i.id, ua.full_name, ua.email, uc.full_name, uc.email`, id,
	).Scan(
		&inc.ID, &inc.Title, &inc.Description,
		&inc.Severity, &inc.Status,
		&assignedTo, &inc.AssignedToName,
		&createdBy, &inc.CreatedByName,
		&inc.AlertCount,
		&inc.CreatedAt, &inc.UpdatedAt, &inc.ResolvedAt,
	)
	if err != nil {
		return nil, err
	}
	inc.AssignedTo = assignedTo
	inc.CreatedBy = createdBy
	return inc, nil
}

// Insert creates a new incident.
func (s *IncidentStore) Insert(ctx context.Context, inc *Incident) (string, error) {
	var id string
	err := s.pool.QueryRow(ctx, `
		INSERT INTO incidents (title, description, severity, status, created_by)
		VALUES ($1, $2, $3, $4, $5::uuid)
		RETURNING id`,
		inc.Title, inc.Description, inc.Severity, inc.Status,
		nilIfEmpty(inc.CreatedBy),
	).Scan(&id)
	return id, err
}

// Update updates incident fields.
func (s *IncidentStore) Update(ctx context.Context, id, title, description, status string, severity int, assignedTo *string) error {
	var resolvedAt interface{}
	if status == "resolved" || status == "closed" {
		resolvedAt = time.Now()
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE incidents
		SET title=$2, description=$3, status=$4, severity=$5,
		    assigned_to=$6::uuid, updated_at=NOW(),
		    resolved_at=COALESCE($7, resolved_at)
		WHERE id=$1`,
		id, title, description, status, severity,
		nilIfEmpty(assignedTo), resolvedAt,
	)
	return err
}

// Delete removes an incident and its alert links.
func (s *IncidentStore) Delete(ctx context.Context, id string) error {
	// Nullify references in tables without ON DELETE CASCADE before deleting.
	_, _ = s.pool.Exec(ctx, "UPDATE correlation_groups SET incident_id = NULL WHERE incident_id = $1", id)

	result, err := s.pool.Exec(ctx, "DELETE FROM incidents WHERE id = $1", id)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("not found")
	}
	return nil
}

// ListAlerts returns alerts linked to an incident.
func (s *IncidentStore) ListAlerts(ctx context.Context, incidentID string) ([]*IncidentAlert, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT ia.alert_id,
		       COALESCE(al.title,''),
		       COALESCE(al.severity, 0),
		       COALESCE(al.status,''),
		       COALESCE(ag.hostname,''),
		       COALESCE(al.mitre_technique,''),
		       COALESCE(al.created_at, ia.linked_at),
		       ia.linked_at
		FROM incident_alerts ia
		LEFT JOIN alerts al ON al.id::text = ia.alert_id
		LEFT JOIN agents ag ON ag.id = al.agent_id
		WHERE ia.incident_id = $1
		ORDER BY ia.linked_at DESC`, incidentID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var alerts []*IncidentAlert
	for rows.Next() {
		a := &IncidentAlert{}
		if err := rows.Scan(&a.AlertID, &a.Title, &a.Severity, &a.Status, &a.Hostname, &a.MITRETechnique, &a.CreatedAt, &a.LinkedAt); err != nil {
			continue
		}
		alerts = append(alerts, a)
	}
	if alerts == nil {
		alerts = []*IncidentAlert{}
	}
	return alerts, nil
}

// LinkAlert adds an alert to an incident.
func (s *IncidentStore) LinkAlert(ctx context.Context, incidentID, alertID string) error {
	_, err := s.pool.Exec(ctx,
		"INSERT INTO incident_alerts (incident_id, alert_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
		incidentID, alertID,
	)
	return err
}

// UnlinkAlert removes an alert from an incident.
func (s *IncidentStore) UnlinkAlert(ctx context.Context, incidentID, alertID string) error {
	_, err := s.pool.Exec(ctx,
		"DELETE FROM incident_alerts WHERE incident_id=$1 AND alert_id=$2",
		incidentID, alertID,
	)
	return err
}

// IncidentNote is a timestamped comment on an incident.
type IncidentNote struct {
	ID         string    `json:"id"`
	IncidentID string    `json:"incident_id"`
	UserID     *string   `json:"user_id,omitempty"`
	UserName   string    `json:"user_name"`
	Body       string    `json:"body"`
	CreatedAt  time.Time `json:"created_at"`
}

// ListNotes returns notes for an incident, newest first.
func (s *IncidentStore) ListNotes(ctx context.Context, incidentID string) ([]*IncidentNote, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT n.id, n.incident_id::text, n.user_id::text,
		       COALESCE(NULLIF(u.full_name,''), u.email, 'System'),
		       n.body, n.created_at
		FROM incident_notes n
		LEFT JOIN users u ON u.id = n.user_id
		WHERE n.incident_id = $1
		ORDER BY n.created_at DESC`, incidentID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var notes []*IncidentNote
	for rows.Next() {
		n := &IncidentNote{}
		var userID *string
		if err := rows.Scan(&n.ID, &n.IncidentID, &userID, &n.UserName, &n.Body, &n.CreatedAt); err != nil {
			continue
		}
		n.UserID = userID
		notes = append(notes, n)
	}
	if notes == nil {
		notes = []*IncidentNote{}
	}
	return notes, nil
}

// AddNote inserts a new note on an incident.
func (s *IncidentStore) AddNote(ctx context.Context, incidentID, userID, body string) (*IncidentNote, error) {
	n := &IncidentNote{}
	var uid *string
	err := s.pool.QueryRow(ctx, `
		INSERT INTO incident_notes (incident_id, user_id, body)
		VALUES ($1, $2::uuid, $3)
		RETURNING id, incident_id::text, user_id::text, body, created_at`,
		incidentID, nilIfEmpty(&userID), body,
	).Scan(&n.ID, &n.IncidentID, &uid, &n.Body, &n.CreatedAt)
	if err != nil {
		return nil, err
	}
	n.UserID = uid
	return n, nil
}
