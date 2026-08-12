package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PlaybookConditions defines what alerts trigger this playbook.
type PlaybookConditions struct {
	MinSeverity    int    `json:"min_severity,omitempty"`
	MaxSeverity    int    `json:"max_severity,omitempty"`
	RuleName       string `json:"rule_name,omitempty"`
	Hostname       string `json:"hostname,omitempty"`
	MITRETechnique string `json:"mitre_technique,omitempty"`
	Status         string `json:"status,omitempty"`
}

// PlaybookAction represents a single automated action.
type PlaybookAction struct {
	Type     string `json:"type"`               // isolate_endpoint | create_incident | notify | assign_alert
	Title    string `json:"title,omitempty"`    // for create_incident
	Severity int    `json:"severity,omitempty"` // for create_incident
	Message  string `json:"message,omitempty"`  // for notify
	UserID   string `json:"user_id,omitempty"`  // for assign_alert
}

// Playbook is an automated response workflow.
type Playbook struct {
	ID            string             `json:"id"`
	Name          string             `json:"name"`
	Description   string             `json:"description,omitempty"`
	Conditions    PlaybookConditions `json:"conditions"`
	Actions       []PlaybookAction   `json:"actions"`
	IsActive      bool               `json:"is_active"`
	RunCount      int                `json:"run_count"`
	LastRunAt     *time.Time         `json:"last_run_at,omitempty"`
	CreatedBy     *string            `json:"created_by,omitempty"`
	CreatedByName string             `json:"created_by_name,omitempty"`
	CreatedAt     time.Time          `json:"created_at"`
	UpdatedAt     time.Time          `json:"updated_at"`
}

// PlaybookRun records a single execution of a playbook.
type PlaybookRun struct {
	ID         string           `json:"id"`
	PlaybookID string           `json:"playbook_id"`
	AlertID    string           `json:"alert_id"`
	ActionsRun []PlaybookAction `json:"actions_run"`
	Success    bool             `json:"success"`
	ErrorMsg   string           `json:"error_msg,omitempty"`
	RanAt      time.Time        `json:"ran_at"`
}

// PlaybookStore manages playbook persistence.
type PlaybookStore struct {
	pool *pgxpool.Pool
}

func NewPlaybookStore(db *DB) *PlaybookStore {
	return &PlaybookStore{pool: db.Pool()}
}

// List returns all playbooks, newest first.
func (s *PlaybookStore) List(ctx context.Context, activeOnly bool) ([]*Playbook, error) {
	where := ""
	if activeOnly {
		where = "WHERE p.is_active = TRUE"
	}
	rows, err := s.pool.Query(ctx, `
		SELECT p.id, p.name, COALESCE(p.description,''),
		       p.conditions, p.actions, p.is_active,
		       p.run_count, p.last_run_at,
		       p.created_by::text,
		       COALESCE(NULLIF(u.full_name,''), u.email, ''),
		       p.created_at, p.updated_at
		FROM playbooks p
		LEFT JOIN users u ON u.id = p.created_by
		`+where+`
		ORDER BY p.created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var playbooks []*Playbook
	for rows.Next() {
		p := &Playbook{}
		var condJSON, actJSON []byte
		var createdBy *string
		if err := rows.Scan(
			&p.ID, &p.Name, &p.Description,
			&condJSON, &actJSON, &p.IsActive,
			&p.RunCount, &p.LastRunAt,
			&createdBy, &p.CreatedByName,
			&p.CreatedAt, &p.UpdatedAt,
		); err != nil {
			continue
		}
		_ = json.Unmarshal(condJSON, &p.Conditions)
		_ = json.Unmarshal(actJSON, &p.Actions)
		if p.Actions == nil {
			p.Actions = []PlaybookAction{}
		}
		p.CreatedBy = createdBy
		playbooks = append(playbooks, p)
	}
	if playbooks == nil {
		playbooks = []*Playbook{}
	}
	return playbooks, nil
}

// Get retrieves a single playbook.
func (s *PlaybookStore) Get(ctx context.Context, id string) (*Playbook, error) {
	p := &Playbook{}
	var condJSON, actJSON []byte
	var createdBy *string
	err := s.pool.QueryRow(ctx, `
		SELECT p.id, p.name, COALESCE(p.description,''),
		       p.conditions, p.actions, p.is_active,
		       p.run_count, p.last_run_at,
		       p.created_by::text,
		       COALESCE(NULLIF(u.full_name,''), u.email, ''),
		       p.created_at, p.updated_at
		FROM playbooks p
		LEFT JOIN users u ON u.id = p.created_by
		WHERE p.id = $1`, id,
	).Scan(
		&p.ID, &p.Name, &p.Description,
		&condJSON, &actJSON, &p.IsActive,
		&p.RunCount, &p.LastRunAt,
		&createdBy, &p.CreatedByName,
		&p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(condJSON, &p.Conditions)
	_ = json.Unmarshal(actJSON, &p.Actions)
	if p.Actions == nil {
		p.Actions = []PlaybookAction{}
	}
	p.CreatedBy = createdBy
	return p, nil
}

// Insert creates a new playbook, returning the new ID.
func (s *PlaybookStore) Insert(ctx context.Context, p *Playbook) (string, error) {
	condJSON, err := json.Marshal(p.Conditions)
	if err != nil {
		return "", err
	}
	actJSON, err := json.Marshal(p.Actions)
	if err != nil {
		return "", err
	}
	var id string
	err = s.pool.QueryRow(ctx, `
		INSERT INTO playbooks (name, description, conditions, actions, is_active, created_by)
		VALUES ($1, $2, $3, $4, $5, $6::uuid)
		RETURNING id`,
		p.Name, p.Description, string(condJSON), string(actJSON),
		p.IsActive, nilIfEmpty(p.CreatedBy),
	).Scan(&id)
	return id, err
}

// Update replaces a playbook's editable fields.
func (s *PlaybookStore) Update(ctx context.Context, p *Playbook) error {
	condJSON, err := json.Marshal(p.Conditions)
	if err != nil {
		return err
	}
	actJSON, err := json.Marshal(p.Actions)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
		UPDATE playbooks
		SET name=$2, description=$3, conditions=$4, actions=$5, is_active=$6, updated_at=NOW()
		WHERE id=$1`,
		p.ID, p.Name, p.Description, string(condJSON), string(actJSON), p.IsActive,
	)
	return err
}

// Delete removes a playbook.
func (s *PlaybookStore) Delete(ctx context.Context, id string) error {
	result, err := s.pool.Exec(ctx, "DELETE FROM playbooks WHERE id = $1", id)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("not found")
	}
	return nil
}

// SetActive toggles the is_active flag.
func (s *PlaybookStore) SetActive(ctx context.Context, id string, active bool) error {
	_, err := s.pool.Exec(ctx,
		"UPDATE playbooks SET is_active=$2, updated_at=NOW() WHERE id=$1",
		id, active,
	)
	return err
}

// ListActiveForAlert returns active playbooks whose conditions match the given alert fields.
func (s *PlaybookStore) ListActiveForAlert(ctx context.Context, severity int, ruleName, hostname, mitreTechnique, status string) ([]*Playbook, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, conditions, actions
		FROM playbooks
		WHERE is_active = TRUE
		ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var matched []*Playbook
	for rows.Next() {
		var id string
		var condJSON, actJSON []byte
		if err := rows.Scan(&id, &condJSON, &actJSON); err != nil {
			continue
		}
		var cond PlaybookConditions
		_ = json.Unmarshal(condJSON, &cond)

		// Apply condition filters
		if cond.MinSeverity > 0 && severity < cond.MinSeverity {
			continue
		}
		if cond.MaxSeverity > 0 && severity > cond.MaxSeverity {
			continue
		}
		if cond.RuleName != "" && !containsStr(ruleName, cond.RuleName) {
			continue
		}
		if cond.Hostname != "" && !containsStr(hostname, cond.Hostname) {
			continue
		}
		if cond.MITRETechnique != "" && !containsStr(mitreTechnique, cond.MITRETechnique) {
			continue
		}
		if cond.Status != "" && status != cond.Status {
			continue
		}

		var actions []PlaybookAction
		_ = json.Unmarshal(actJSON, &actions)

		matched = append(matched, &Playbook{ID: id, Conditions: cond, Actions: actions})
	}
	return matched, nil
}

// RecordRun logs a playbook execution.
func (s *PlaybookStore) RecordRun(ctx context.Context, run *PlaybookRun) error {
	actJSON, _ := json.Marshal(run.ActionsRun)
	errMsg := run.ErrorMsg
	_, err := s.pool.Exec(ctx, `
		INSERT INTO playbook_runs (playbook_id, alert_id, actions_run, success, error_msg)
		VALUES ($1::uuid, $2, $3, $4, $5)`,
		run.PlaybookID, run.AlertID, string(actJSON), run.Success, errMsg,
	)
	if err != nil {
		return err
	}
	// Increment run counter and update last_run_at
	_, err = s.pool.Exec(ctx,
		"UPDATE playbooks SET run_count=run_count+1, last_run_at=NOW(), updated_at=NOW() WHERE id=$1",
		run.PlaybookID,
	)
	return err
}

// ListRuns returns recent execution history for a playbook.
func (s *PlaybookStore) ListRuns(ctx context.Context, playbookID string, limit int) ([]*PlaybookRun, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, playbook_id::text, alert_id, actions_run, success, COALESCE(error_msg,''), ran_at
		FROM playbook_runs
		WHERE playbook_id = $1::uuid
		ORDER BY ran_at DESC
		LIMIT $2`, playbookID, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var runs []*PlaybookRun
	for rows.Next() {
		r := &PlaybookRun{}
		var actJSON []byte
		if err := rows.Scan(&r.ID, &r.PlaybookID, &r.AlertID, &actJSON, &r.Success, &r.ErrorMsg, &r.RanAt); err != nil {
			continue
		}
		_ = json.Unmarshal(actJSON, &r.ActionsRun)
		runs = append(runs, r)
	}
	if runs == nil {
		runs = []*PlaybookRun{}
	}
	return runs, nil
}

// containsStr checks if s contains sub (case-insensitive substring).
func containsStr(s, sub string) bool {
	if len(s) < len(sub) {
		return false
	}
	sl := toLower(s)
	subl := toLower(sub)
	for i := 0; i <= len(sl)-len(subl); i++ {
		if sl[i:i+len(subl)] == subl {
			return true
		}
	}
	return false
}

func toLower(s string) string {
	b := make([]byte, len(s))
	for i := range s {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		b[i] = c
	}
	return string(b)
}
