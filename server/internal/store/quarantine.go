package store

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// QuarantinedFile represents a file quarantined on an agent.
type QuarantinedFile struct {
	ID            string     `json:"id"`
	AgentID       string     `json:"agent_id"`
	AgentHostname *string    `json:"agent_hostname,omitempty"`
	AlertID       *string    `json:"alert_id,omitempty"`
	OriginalPath  string     `json:"original_path"`
	FileSize      *int64     `json:"file_size,omitempty"`
	HashMD5       *string    `json:"hash_md5,omitempty"`
	HashSHA256    *string    `json:"hash_sha256,omitempty"`
	QuarantinedAt time.Time  `json:"quarantined_at"`
	RestoredAt    *time.Time `json:"restored_at,omitempty"`
	RestoredBy    *string    `json:"restored_by,omitempty"`
}

// QuarantineStore handles quarantined file database operations.
type QuarantineStore struct {
	pool *pgxpool.Pool
}

func NewQuarantineStore(db *DB) *QuarantineStore {
	return &QuarantineStore{pool: db.Pool()}
}

// QuarantineFilter holds optional search/filter params.
type QuarantineFilter struct {
	AgentID string // exact match
	Search  string // partial match on original_path or hash_sha256
	Status  string // "quarantined" | "restored" | "" (all)
}

// List returns quarantined files with optional filtering.
// quarantineListWhere builds the WHERE clause and arguments for List.
//
// **切り出してあるのは、検査が本物を呼べるようにするためです。**
// 検査ファイルには同じ組み立ての写しが置いてあり、そちらだけが試されて
// いました。公開はしません —— `List` からしか使わないので、公開すると
// `TestStoreSymbolsAreReachable` の数が増えます。
func quarantineListWhere(f QuarantineFilter) (string, []interface{}) {
	conds := []string{"1=1"}
	args := []interface{}{}
	i := 1

	if f.AgentID != "" {
		conds = append(conds, fmt.Sprintf("agent_id = $%d", i))
		args = append(args, f.AgentID)
		i++
	}
	if f.Search != "" {
		conds = append(conds, fmt.Sprintf("(original_path ILIKE $%d OR hash_sha256 ILIKE $%d)", i, i))
		args = append(args, "%"+f.Search+"%")
		i++
	}
	if f.Status == "quarantined" {
		conds = append(conds, "restored_at IS NULL")
	} else if f.Status == "restored" {
		conds = append(conds, "restored_at IS NOT NULL")
	}

	where := "WHERE " + conds[0]
	for _, c := range conds[1:] {
		where += " AND " + c
	}
	return where, args
}

func (s *QuarantineStore) List(ctx context.Context, f QuarantineFilter, limit, offset int) ([]*QuarantinedFile, int, error) {
	where, args := quarantineListWhere(f)
	i := len(args) + 1

	var total int
	if err := s.pool.QueryRow(ctx, "SELECT COUNT(*) FROM quarantined_files "+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	args = append(args, limit, offset)
	rows, err := s.pool.Query(ctx, `
		SELECT qf.id, qf.agent_id, qf.alert_id, qf.original_path, qf.file_size,
		       qf.hash_md5, qf.hash_sha256, qf.quarantined_at, qf.restored_at, qf.restored_by,
		       a.hostname
		FROM quarantined_files qf
		LEFT JOIN agents a ON a.id = qf.agent_id
		`+where+`
		ORDER BY qf.quarantined_at DESC
		LIMIT $`+fmt.Sprintf("%d", i)+` OFFSET $`+fmt.Sprintf("%d", i+1),
		args...,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var files []*QuarantinedFile
	for rows.Next() {
		var f QuarantinedFile
		if err := rows.Scan(
			&f.ID, &f.AgentID, &f.AlertID, &f.OriginalPath, &f.FileSize,
			&f.HashMD5, &f.HashSHA256, &f.QuarantinedAt, &f.RestoredAt, &f.RestoredBy,
			&f.AgentHostname,
		); err != nil {
			continue
		}
		files = append(files, &f)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return files, total, nil
}

const insertQuarantineSQL = `
	INSERT INTO quarantined_files (agent_id, alert_id, original_path, file_size, hash_md5, hash_sha256, agent_quarantine_id)
	VALUES ($1, $2, $3, $4, $5, $6, $7)
	RETURNING id, agent_id, alert_id, original_path, file_size, hash_md5, hash_sha256, quarantined_at`

// Record inserts a quarantine record (called when the agent reports a successful quarantine).
// agentQuarantineID is the agent-local identifier (LinuxFileQuarantine UUID etc.)
// — required so a future Restore call can ask the agent to find this file again.
//
// alertID is accepted only when it is a valid UUID. On FK violation (alert deleted
// between command dispatch and agent completion) the insert is retried with
// alert_id = NULL so the quarantine record is always persisted.
func (s *QuarantineStore) Record(ctx context.Context, agentID, alertID, path string, fileSize *int64, md5, sha256, agentQuarantineID string) (*QuarantinedFile, error) {
	var f QuarantinedFile

	// Only pass alert_id when it is a parseable UUID; non-UUID strings (e.g. from
	// legacy NATS auto-response commands) would fail the column cast at the DB.
	var alertIDArg *string
	if alertID != "" {
		if _, err := uuid.Parse(alertID); err == nil {
			alertIDArg = &alertID
		}
	}
	var md5Arg, sha256Arg, aqidArg *string
	if md5 != "" {
		md5Arg = &md5
	}
	if sha256 != "" {
		sha256Arg = &sha256
	}
	if agentQuarantineID != "" {
		aqidArg = &agentQuarantineID
	}

	err := s.pool.QueryRow(ctx, insertQuarantineSQL,
		agentID, alertIDArg, path, fileSize, md5Arg, sha256Arg, aqidArg,
	).Scan(
		&f.ID, &f.AgentID, &f.AlertID, &f.OriginalPath, &f.FileSize,
		&f.HashMD5, &f.HashSHA256, &f.QuarantinedAt,
	)
	if err != nil && alertIDArg != nil {
		// The INSERT failed while alert_id was non-nil. Most common cause: the
		// referenced alert was deleted after the quarantine command was dispatched
		// (FK violation). Retry with NULL so the quarantine record is always
		// persisted regardless of alert lifecycle. If the retry also fails (e.g.
		// agent_id FK), that error is returned to the caller.
		slog.Warn("quarantine.Record: alert_id FK violation; retrying with NULL", "agent", agentID, "alert_id", alertID, "error", err)
		alertIDArg = nil
		err = s.pool.QueryRow(ctx, insertQuarantineSQL,
			agentID, alertIDArg, path, fileSize, md5Arg, sha256Arg, aqidArg,
		).Scan(
			&f.ID, &f.AgentID, &f.AlertID, &f.OriginalPath, &f.FileSize,
			&f.HashMD5, &f.HashSHA256, &f.QuarantinedAt,
		)
	}
	return &f, err
}

// GetAgentQuarantineID returns the agent-local quarantine identifier so
// the server can issue restore commands the agent will actually recognize.
// Empty string is returned for legacy records that predate the column.
func (s *QuarantineStore) GetAgentQuarantineID(ctx context.Context, id string) (string, error) {
	var aqid *string
	err := s.pool.QueryRow(ctx,
		`SELECT agent_quarantine_id FROM quarantined_files WHERE id = $1`, id,
	).Scan(&aqid)
	if err != nil {
		return "", err
	}
	if aqid == nil {
		return "", nil
	}
	return *aqid, nil
}

// GetAgentID returns the owning agent for a quarantine record. Used by the
// Restore handler so the caller doesn't have to round-trip the agent_id —
// the bulk-release UI in particular fires the request without a body.
func (s *QuarantineStore) GetAgentID(ctx context.Context, id string) (string, error) {
	var agentID string
	err := s.pool.QueryRow(ctx,
		`SELECT agent_id::text FROM quarantined_files WHERE id = $1`, id,
	).Scan(&agentID)
	return agentID, err
}

// MarkRestored marks a quarantine record as restored.
func (s *QuarantineStore) MarkRestored(ctx context.Context, id, restoredBy string) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE quarantined_files
		SET restored_at = NOW(), restored_by = $2
		WHERE id = $1 AND restored_at IS NULL`,
		id, restoredBy,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("quarantine record not found or already restored")
	}
	return nil
}

// Delete permanently removes a quarantine record.
func (s *QuarantineStore) Delete(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, "DELETE FROM quarantined_files WHERE id = $1", id)
	return err
}
