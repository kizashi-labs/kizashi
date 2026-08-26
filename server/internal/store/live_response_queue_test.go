package store

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// live_response_commands is shared by two features with different shapes: the
// interactive terminal (live_response.go), which always has a session, and the
// agent command queue (live_response_store.go), which never does. The column
// set was built for the terminal, and the queue was written against what it
// wished the column set were. Four faults, all reproduced against the migrated
// schema before this change:
//
//	Create without a session   23502 — session_id was NOT NULL, so queueing a
//	                           command outside a terminal session, which is the
//	                           entire purpose of the queue, always 500'd.
//	Cancel                     23514 — status='failed' is not in the CHECK
//	                           (pending/running/completed/error/timeout). Every
//	                           cancellation failed and the command stayed
//	                           pending, while the operator was told the cancel
//	                           had failed and given no way to retry it.
//	UpdateResult("failed")     23514 — and "success" likewise. The submitted
//	                           status went straight into the UPDATE, so the two
//	                           most natural words an agent would send were
//	                           rejected as a 500 that named a constraint.
//	UpdateResult twice         the second result silently replaced the first,
//	                           with nothing recorded to say the first existed.
//
// Every one of these is a write that fails where the caller cannot see it: the
// constraint violation surfaces as a generic 500, and the overwrite surfaces as
// nothing at all.

func lrPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping DB integration tests")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// lrAgent seeds an agent and removes it, and anything queued against it, at the
// end of the test.
func lrAgent(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	ctx := context.Background()
	id := uuid.NewString()
	if _, err := pool.Exec(ctx,
		`INSERT INTO agents (id,hostname,os_type,status,last_seen)
		 VALUES ($1::uuid,'lr-queue-fixture','linux','online',NOW())`, id); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = pool.Exec(c, `DELETE FROM live_response_commands WHERE agent_id=$1::uuid`, id)
		_, _ = pool.Exec(c, `DELETE FROM live_response_sessions WHERE agent_id=$1::uuid`, id)
		_, _ = pool.Exec(c, `DELETE FROM agents WHERE id=$1::uuid`, id)
	})
	return id
}

// lrSession opens a terminal session, the other writer of this table.
func lrSession(t *testing.T, pool *pgxpool.Pool, agentID string) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO live_response_sessions (agent_id, started_by, status, token)
		 VALUES ($1::uuid,'lr-test','active',$2) RETURNING id::text`,
		agentID, uuid.NewString()).Scan(&id); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	return id
}

func queueCmd(t *testing.T, s *CmdQueueStore, agentID string, session *string) QueuedCommand {
	t.Helper()
	cmd, err := s.Create(context.Background(), CreateQueuedCommandInput{
		AgentID: agentID, SessionID: session,
		CommandType: "shell", Command: "ps aux", Args: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatalf("queue command: %v", err)
	}
	return cmd
}

// TestACommandCanBeQueuedWithoutATerminalSession is the core gate. The queue
// exists to send one command to one agent; requiring a terminal session made
// that impossible.
func TestACommandCanBeQueuedWithoutATerminalSession(t *testing.T) {
	pool := lrPool(t)
	agentID := lrAgent(t, pool)
	s := NewCmdQueueStore(pool)

	cmd, err := s.Create(context.Background(), CreateQueuedCommandInput{
		AgentID: agentID, CommandType: "shell", Command: "ps aux", Args: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatalf("queueing a command with no session failed: %v\nThe queue's own "+
			"input type declares SessionID as optional, and there is no terminal "+
			"session involved when an operator queues a single command.", err)
	}
	if cmd.SessionID != nil {
		t.Errorf("session_id = %v, want NULL", *cmd.SessionID)
	}
	if cmd.Status != QueuedCommandPending {
		t.Errorf("status = %q, want %q", cmd.Status, QueuedCommandPending)
	}

	pending, err := s.PendingForAgent(context.Background(), agentID)
	if err != nil {
		t.Fatalf("PendingForAgent: %v", err)
	}
	if len(pending) == 0 {
		t.Error("the queued command is not offered to the agent that must run it")
	}
}

// TestCancellingAQueuedCommandWorks.
func TestCancellingAQueuedCommandWorks(t *testing.T) {
	pool := lrPool(t)
	agentID := lrAgent(t, pool)
	s := NewCmdQueueStore(pool)
	cmd := queueCmd(t, s, agentID, nil)

	if err := s.Cancel(context.Background(), cmd.ID); err != nil {
		t.Fatalf("Cancel: %v\nCancel wrote a status the CHECK constraint on this "+
			"column rejects, so no command has ever been cancellable.", err)
	}

	after, err := s.Get(context.Background(), cmd.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if after.Status == QueuedCommandPending {
		t.Error("the command is still pending after a successful-looking cancel, " +
			"so the agent will pick it up and run it anyway")
	}
	if after.Output == nil || *after.Output == "" {
		t.Error("nothing records why the command ended, so the console cannot tell " +
			"a cancellation from a failure")
	}
	if after.CompletedAt == nil {
		t.Error("completed_at was not set on a cancelled command")
	}
}

// TestCancellingATwiceIsNotSilentlyAccepted keeps Cancel honest about what it
// did: a command that already finished must not be reported as cancelled.
func TestCancellingTwiceIsNotSilentlyAccepted(t *testing.T) {
	pool := lrPool(t)
	agentID := lrAgent(t, pool)
	s := NewCmdQueueStore(pool)
	cmd := queueCmd(t, s, agentID, nil)

	if err := s.Cancel(context.Background(), cmd.ID); err != nil {
		t.Fatalf("first cancel: %v", err)
	}
	if err := s.Cancel(context.Background(), cmd.ID); err == nil {
		t.Error("cancelling an already-finished command reported success")
	}
}

// TestTheStatusWordsAgentsSendAreUnderstood. "failed" and "success" are the
// words the rest of this codebase uses; both were rejected by the CHECK
// constraint and surfaced to the caller as a 500.
func TestTheStatusWordsAgentsSendAreUnderstood(t *testing.T) {
	cases := map[string]string{
		"failed":    QueuedCommandError,
		"FAILED":    QueuedCommandError,
		" failure ": QueuedCommandError,
		"error":     QueuedCommandError,
		"success":   QueuedCommandCompleted,
		"ok":        QueuedCommandCompleted,
		"completed": QueuedCommandCompleted,
		"timeout":   QueuedCommandTimeout,
	}
	for in, want := range cases {
		got, err := NormalizeResultStatus(in)
		if err != nil {
			t.Errorf("NormalizeResultStatus(%q) = error %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("NormalizeResultStatus(%q) = %q, want %q", in, got, want)
		}
	}

	if _, err := NormalizeResultStatus("banana"); !errors.Is(err, ErrUnknownResultStatus) {
		t.Errorf("an unrecognised status returned %v, want ErrUnknownResultStatus — "+
			"without it the word reaches Postgres and comes back as a 500 naming a "+
			"constraint instead of the field", err)
	}
	if _, err := NormalizeResultStatus(""); !errors.Is(err, ErrUnknownResultStatus) {
		t.Errorf("an empty status returned %v, want ErrUnknownResultStatus", err)
	}
}

// TestAResultUsingTheWordFailedIsRecorded is the end-to-end half of the above,
// against the real constraint.
func TestAResultUsingTheWordFailedIsRecorded(t *testing.T) {
	pool := lrPool(t)
	agentID := lrAgent(t, pool)
	s := NewCmdQueueStore(pool)
	cmd := queueCmd(t, s, agentID, nil)

	exit := 127
	applied, err := s.UpdateResult(context.Background(), cmd.ID, "failed", "command not found", &exit)
	if err != nil {
		t.Fatalf(`UpdateResult with status "failed": %v`, err)
	}
	if !applied {
		t.Fatal("the result was not applied to any command")
	}

	after, _ := s.Get(context.Background(), cmd.ID)
	if after.Status != QueuedCommandError {
		t.Errorf("status = %q, want %q", after.Status, QueuedCommandError)
	}
	if after.ExitCode == nil || *after.ExitCode != exit {
		t.Errorf("exit_code = %v, want %d", after.ExitCode, exit)
	}
}

// TestASecondResultDoesNotOverwriteTheFirst. Retries and replays are normal on
// an agent link that drops; whichever result arrived first is the one that
// happened.
func TestASecondResultDoesNotOverwriteTheFirst(t *testing.T) {
	pool := lrPool(t)
	agentID := lrAgent(t, pool)
	s := NewCmdQueueStore(pool)
	cmd := queueCmd(t, s, agentID, nil)

	if applied, err := s.UpdateResult(context.Background(), cmd.ID, "completed", "first", nil); err != nil || !applied {
		t.Fatalf("first result: applied=%v err=%v", applied, err)
	}
	applied, err := s.UpdateResult(context.Background(), cmd.ID, "completed", "second", nil)
	if err != nil {
		t.Fatalf("second result: %v", err)
	}
	if applied {
		t.Error("a second result was accepted for a command that had already " +
			"finished; the caller is told it was recorded")
	}

	after, _ := s.Get(context.Background(), cmd.ID)
	if after.Output == nil || *after.Output != "first" {
		t.Errorf("output = %v, want %q — the recorded outcome was replaced by a "+
			"later delivery", after.Output, "first")
	}
}

// TestAResultForATimedOutCommandIsRejected. The sweeper marks a command timeout
// once its deadline passes; a result arriving afterwards must not resurrect it,
// or a command the operator was told had timed out silently becomes successful.
func TestAResultForATimedOutCommandIsRejected(t *testing.T) {
	pool := lrPool(t)
	agentID := lrAgent(t, pool)
	s := NewCmdQueueStore(pool)
	cmd := queueCmd(t, s, agentID, nil)

	if _, err := pool.Exec(context.Background(),
		`UPDATE live_response_commands SET timeout_at = NOW() - INTERVAL '1 minute' WHERE id=$1::uuid`,
		cmd.ID); err != nil {
		t.Fatalf("age the command: %v", err)
	}
	if _, err := s.TimeoutStale(context.Background()); err != nil {
		t.Fatalf("TimeoutStale: %v", err)
	}
	if got, _ := s.Get(context.Background(), cmd.ID); got.Status != QueuedCommandTimeout {
		t.Fatalf("status = %q after the sweep, want %q", got.Status, QueuedCommandTimeout)
	}

	applied, err := s.UpdateResult(context.Background(), cmd.ID, "completed", "late", nil)
	if err != nil {
		t.Fatalf("late result: %v", err)
	}
	if applied {
		t.Error("a result was accepted for a command that had already timed out")
	}
}

// TestATimedOutCommandIsNotOfferedToTheAgent is the floor on the other side: an
// expired command must not be handed out for execution.
func TestATimedOutCommandIsNotOfferedToTheAgent(t *testing.T) {
	pool := lrPool(t)
	agentID := lrAgent(t, pool)
	s := NewCmdQueueStore(pool)
	cmd := queueCmd(t, s, agentID, nil)

	if _, err := pool.Exec(context.Background(),
		`UPDATE live_response_commands SET timeout_at = NOW() - INTERVAL '1 minute' WHERE id=$1::uuid`,
		cmd.ID); err != nil {
		t.Fatalf("age the command: %v", err)
	}
	pending, err := s.PendingForAgent(context.Background(), agentID)
	if err != nil {
		t.Fatalf("PendingForAgent: %v", err)
	}
	for _, p := range pending {
		if p.ID == cmd.ID {
			t.Error("an expired command is still offered to the agent")
		}
	}
}

// TestTheTerminalFeatureStillWorks. Both features write this table, and this
// change loosened a constraint the terminal relies on; its own path has to keep
// behaving.
func TestTheTerminalFeatureStillWorks(t *testing.T) {
	pool := lrPool(t)
	agentID := lrAgent(t, pool)
	sessionID := lrSession(t, pool, agentID)
	lr := NewLiveResponseStore(&DB{pool: pool})
	ctx := context.Background()

	cmd, err := lr.EnqueueCommand(ctx, sessionID, "uname -a", "operator")
	if err != nil {
		t.Fatalf("EnqueueCommand: %v", err)
	}
	if cmd.Status != QueuedCommandPending {
		t.Errorf("status = %q, want %q", cmd.Status, QueuedCommandPending)
	}

	dequeued, err := lr.DequeuePendingCommands(ctx, sessionID)
	if err != nil {
		t.Fatalf("DequeuePendingCommands: %v", err)
	}
	if len(dequeued) != 1 {
		t.Fatalf("dequeued %d commands, want 1", len(dequeued))
	}
	if err := lr.CompleteCommand(ctx, cmd.ID, "Linux", 0, false); err != nil {
		t.Fatalf("CompleteCommand: %v", err)
	}

	list, err := lr.ListCommands(ctx, sessionID)
	if err != nil {
		t.Fatalf("ListCommands: %v", err)
	}
	if len(list) != 1 || list[0].Status != QueuedCommandCompleted {
		t.Errorf("terminal command list = %+v", list)
	}

	// And a session-less queue row must not appear in a session's history.
	q := NewCmdQueueStore(pool)
	queueCmd(t, q, agentID, nil)
	list, err = lr.ListCommands(ctx, sessionID)
	if err != nil {
		t.Fatalf("ListCommands: %v", err)
	}
	if len(list) != 1 {
		t.Errorf("the terminal session now shows %d commands; a queued command with "+
			"no session leaked into a session's history", len(list))
	}
}
