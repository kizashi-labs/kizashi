package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// QueuedCommand represents a command in the live response command queue.
type QueuedCommand struct {
	ID          string          `json:"id"`
	AgentID     string          `json:"agent_id"`
	SessionID   *string         `json:"session_id,omitempty"`
	CommandType string          `json:"command_type"`
	Command     string          `json:"command"`
	Args        json.RawMessage `json:"args"`
	Status      string          `json:"status"`
	Output      *string         `json:"output,omitempty"`
	ExitCode    *int            `json:"exit_code,omitempty"`
	CreatedBy   *string         `json:"created_by,omitempty"`
	CreatedAt   time.Time       `json:"created_at"`
	StartedAt   *time.Time      `json:"started_at,omitempty"`
	CompletedAt *time.Time      `json:"completed_at,omitempty"`
	TimeoutAt   time.Time       `json:"timeout_at"`
}

// CreateQueuedCommandInput holds the input for creating a new queued command.
type CreateQueuedCommandInput struct {
	AgentID     string          `json:"agent_id"`
	SessionID   *string         `json:"session_id,omitempty"`
	CommandType string          `json:"command_type"`
	Command     string          `json:"command"`
	Args        json.RawMessage `json:"args"`
	CreatedBy   *string         `json:"created_by,omitempty"`
}

// CmdQueueStore manages the live response command queue.
type CmdQueueStore struct {
	pool *pgxpool.Pool
}

// NewCmdQueueStore creates a new CmdQueueStore backed by the provided pool.
func NewCmdQueueStore(pool *pgxpool.Pool) *CmdQueueStore {
	return &CmdQueueStore{pool: pool}
}

func (s *CmdQueueStore) scanCommand(row interface {
	Scan(dest ...any) error
}) (QueuedCommand, error) {
	var cmd QueuedCommand
	err := row.Scan(
		&cmd.ID, &cmd.AgentID, &cmd.SessionID, &cmd.CommandType, &cmd.Command, &cmd.Args,
		&cmd.Status, &cmd.Output, &cmd.ExitCode, &cmd.CreatedBy,
		&cmd.CreatedAt, &cmd.StartedAt, &cmd.CompletedAt, &cmd.TimeoutAt,
	)
	return cmd, err
}

const cmdQueueColumns = `id, agent_id, session_id, command_type, command, args, status, output, exit_code, created_by, created_at, started_at, completed_at, timeout_at`

// Create inserts a new pending command into the queue.
func (s *CmdQueueStore) Create(ctx context.Context, in CreateQueuedCommandInput) (QueuedCommand, error) {
	if in.Args == nil {
		in.Args = json.RawMessage("{}")
	}
	// live_response_commands.input is NOT NULL (shared with the live-response
	// terminal feature, whose EnqueueCommand stores the command text there).
	// Mirror that here so queued commands insert successfully; input carries the
	// same command text as the command column.
	row := s.pool.QueryRow(ctx,
		`INSERT INTO live_response_commands (agent_id, session_id, command_type, command, input, args, created_by)
		 VALUES ($1,$2,$3,$4,$4,$5,$6)
		 RETURNING `+cmdQueueColumns,
		in.AgentID, in.SessionID, in.CommandType, in.Command, in.Args, in.CreatedBy,
	)
	return s.scanCommand(row)
}

// Get retrieves a single command by its ID.
func (s *CmdQueueStore) Get(ctx context.Context, id string) (QueuedCommand, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+cmdQueueColumns+`
		 FROM live_response_commands WHERE id=$1`, id,
	)
	cmd, err := s.scanCommand(row)
	if err != nil {
		return cmd, fmt.Errorf("command not found: %w", err)
	}
	return cmd, nil
}

// ListByAgent returns commands for an agent, newest first.
func (s *CmdQueueStore) ListByAgent(ctx context.Context, agentID string, limit int) ([]QueuedCommand, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx,
		`SELECT `+cmdQueueColumns+`
		 FROM live_response_commands WHERE agent_id=$1 ORDER BY created_at DESC LIMIT $2`,
		agentID, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []QueuedCommand
	for rows.Next() {
		cmd, err := s.scanCommand(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, cmd)
	}
	if result == nil {
		result = []QueuedCommand{}
	}
	return result, rows.Err()
}

// PendingForAgent returns pending (non-timed-out) commands for an agent to pick up.
func (s *CmdQueueStore) PendingForAgent(ctx context.Context, agentID string) ([]QueuedCommand, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+cmdQueueColumns+`
		 FROM live_response_commands
		 WHERE agent_id=$1 AND status='pending' AND timeout_at > NOW()
		 ORDER BY created_at ASC LIMIT 10`,
		agentID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []QueuedCommand
	for rows.Next() {
		cmd, err := s.scanCommand(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, cmd)
	}
	if result == nil {
		result = []QueuedCommand{}
	}
	return result, rows.Err()
}

// UpdateResult records the output submitted by an agent when a command finishes.
func (s *CmdQueueStore) UpdateResult(ctx context.Context, id, status, output string, exitCode *int) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE live_response_commands
		 SET status=$1, output=$2, exit_code=$3, completed_at=NOW()
		 WHERE id=$4`,
		status, output, exitCode, id,
	)
	return err
}

// Cancel sets a pending command to failed (cancelled).
func (s *CmdQueueStore) Cancel(ctx context.Context, id string) error {
	result, err := s.pool.Exec(ctx,
		`UPDATE live_response_commands SET status='failed', output='キャンセルされました', completed_at=NOW()
		 WHERE id=$1 AND status='pending'`, id)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("command not found or not cancellable")
	}
	return nil
}

// TimeoutStale marks pending/running commands that have passed their timeout_at as timed out.
func (s *CmdQueueStore) TimeoutStale(ctx context.Context) (int64, error) {
	result, err := s.pool.Exec(ctx,
		`UPDATE live_response_commands SET status='timeout', completed_at=NOW()
		 WHERE status IN ('pending','running') AND timeout_at < NOW()`)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected(), nil
}
