// Package rollback — service.go wires the pure rollback planner to the
// remediation_journal table (Ph2 of docs/design/ロールバック(Storyline相当)設計.md):
// record file changes attributed to an incident, and build/execute-bookkeep the
// rollback plan. The inversion logic itself stays in the pure Plan (rollback.go);
// this layer only persists and loads journal entries.
package rollback

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// RollbackDB is the slice of *pgxpool.Pool the service needs (a pool satisfies it
// directly; tests fake it).
type RollbackDB interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// RollbackService records reversible file changes and plans their reversal.
type RollbackService struct {
	db RollbackDB
}

// NewRollbackService builds a service over the given pool.
func NewRollbackService(db RollbackDB) *RollbackService {
	return &RollbackService{db: db}
}

// ChangeRecord is a reversible file-system change to append to the journal.
type ChangeRecord struct {
	IncidentID string
	AlertID    string
	AgentID    string
	Path       string
	Operation  string // OpCreate | OpModify | OpDelete | "rename"
	BackupRef  string // pre-image backup id (modify/delete); empty otherwise
	OldPath    string // rename source
	OccurredAt time.Time
}

// RecordChange appends one reversible change to the remediation journal.
func (s *RollbackService) RecordChange(ctx context.Context, c ChangeRecord) error {
	occurred := c.OccurredAt
	if occurred.IsZero() {
		occurred = time.Now()
	}
	_, err := s.db.Exec(ctx,
		`INSERT INTO remediation_journal
		   (incident_id, alert_id, agent_id, path, operation, backup_ref, old_path, occurred_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		c.IncidentID, nullIfEmpty(c.AlertID), c.AgentID, c.Path, c.Operation,
		nullIfEmpty(c.BackupRef), nullIfEmpty(c.OldPath), occurred,
	)
	return err
}

// Plan loads an incident's un-reverted journal entries and reconstructs the inverse
// operations that restore the pre-incident state.
func (s *RollbackService) Plan(ctx context.Context, incidentID string) (RollbackPlan, error) {
	rows, err := s.db.Query(ctx,
		`SELECT path, operation, COALESCE(backup_ref, ''), occurred_at
		   FROM remediation_journal
		  WHERE incident_id = $1 AND reverted = FALSE
		  ORDER BY occurred_at`,
		incidentID,
	)
	if err != nil {
		return RollbackPlan{}, err
	}
	defer rows.Close()

	var entries []JournalEntry
	for rows.Next() {
		var e JournalEntry
		if err := rows.Scan(&e.Path, &e.Operation, &e.BackupRef, &e.OccurredAt); err != nil {
			return RollbackPlan{}, err
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return RollbackPlan{}, err
	}
	return Plan(incidentID, entries), nil
}

// Preview is Plan under an analyst-facing name: the rollback is a destructive action,
// so the plan must be reviewed before execution (no auto-apply).
func (s *RollbackService) Preview(ctx context.Context, incidentID string) (RollbackPlan, error) {
	return s.Plan(ctx, incidentID)
}

// MarkReverted flags the given paths' journal entries for an incident as reverted,
// after the agent has executed the inverse operations. Returns rows updated.
func (s *RollbackService) MarkReverted(ctx context.Context, incidentID string, paths []string) (int, error) {
	if len(paths) == 0 {
		return 0, nil
	}
	tag, err := s.db.Exec(ctx,
		`UPDATE remediation_journal
		    SET reverted = TRUE, reverted_at = NOW()
		  WHERE incident_id = $1 AND path = ANY($2) AND reverted = FALSE`,
		incidentID, paths,
	)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

// nullIfEmpty maps "" to nil so empty optional columns store SQL NULL, not ”.
func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
