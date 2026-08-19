package handlers_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/edr-platform/server/internal/api/handlers"
	"github.com/edr-platform/server/internal/store"
)

// POST /api/v1/agent/commands/:cmd_id/result passed the submitted status
// straight into the UPDATE. live_response_commands.status carries a CHECK
// constraint allowing pending/running/completed/error/timeout, so an agent
// reporting "failed" or "success" — the two most natural words, and the ones
// used elsewhere in this codebase — got a 500 whose only clue was a constraint
// name in the server log. A second result for the same command was accepted and
// silently replaced the first.
//
// These tests drive the handler against the real database.

func lrCmdPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	return testPool(t)
}

// seedQueuedCommand puts one pending command in the queue and returns its id.
func seedQueuedCommand(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	ctx := context.Background()
	agentID := uuid.NewString()
	if _, err := pool.Exec(ctx,
		`INSERT INTO agents (id,hostname,os_type,status,last_seen)
		 VALUES ($1::uuid,'lr-result-fixture','linux','online',NOW())`, agentID); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = pool.Exec(c, `DELETE FROM live_response_commands WHERE agent_id=$1::uuid`, agentID)
		_, _ = pool.Exec(c, `DELETE FROM agents WHERE id=$1::uuid`, agentID)
	})
	cmd, err := store.NewCmdQueueStore(pool).Create(ctx, store.CreateQueuedCommandInput{
		AgentID: agentID, CommandType: "shell", Command: "ps aux", Args: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatalf("queue command: %v", err)
	}
	return cmd.ID
}

// postResult calls SubmitResult with the given cmd_id and body.
func postResult(t *testing.T, h *handlers.LiveResponseCmdHandler, cmdID, body string) (int, string) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost,
		"/api/v1/agent/commands/"+cmdID+"/result", strings.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Params = gin.Params{{Key: "cmd_id", Value: cmdID}}
	h.SubmitResult(c)
	return w.Code, w.Body.String()
}

// TestAnAgentCanReportFailure is the core gate.
func TestAnAgentCanReportFailure(t *testing.T) {
	pool := lrCmdPool(t)
	h := handlers.NewLiveResponseCmdHandler(store.NewCmdQueueStore(pool))
	cmdID := seedQueuedCommand(t, pool)

	code, body := postResult(t, h, cmdID, `{"status":"failed","output":"not found","exit_code":127}`)
	if code != http.StatusOK {
		t.Fatalf("status = %d (body: %s). An agent reporting a failed command was "+
			"answered with a server error, because the word it sent is not one the "+
			"CHECK constraint accepts.", code, body)
	}

	var got string
	if err := pool.QueryRow(context.Background(),
		`SELECT status FROM live_response_commands WHERE id=$1::uuid`, cmdID).Scan(&got); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if got != store.QueuedCommandError {
		t.Errorf("status = %q, want %q", got, store.QueuedCommandError)
	}
}

// TestAnUnknownStatusIsARequestError. The caller sent a word this system does
// not use; saying so is a 400. Answering 500 blames the server and gives the
// agent author nothing to act on.
func TestAnUnknownStatusIsARequestError(t *testing.T) {
	pool := lrCmdPool(t)
	h := handlers.NewLiveResponseCmdHandler(store.NewCmdQueueStore(pool))
	cmdID := seedQueuedCommand(t, pool)

	code, body := postResult(t, h, cmdID, `{"status":"banana","output":""}`)
	if code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (body: %s)", code, body)
	}
	if !strings.Contains(body, "banana") {
		t.Errorf("the response does not name the offending value: %s", body)
	}
}

// TestASecondResultIsRejected. A retry or a replay must not overwrite the
// outcome that was already recorded.
func TestASecondResultIsRejected(t *testing.T) {
	pool := lrCmdPool(t)
	h := handlers.NewLiveResponseCmdHandler(store.NewCmdQueueStore(pool))
	cmdID := seedQueuedCommand(t, pool)

	if code, body := postResult(t, h, cmdID, `{"status":"completed","output":"first"}`); code != http.StatusOK {
		t.Fatalf("first result: status = %d (body: %s)", code, body)
	}
	code, body := postResult(t, h, cmdID, `{"status":"completed","output":"second"}`)
	if code != http.StatusConflict {
		t.Errorf("second result: status = %d, want 409 (body: %s)", code, body)
	}

	var out string
	if err := pool.QueryRow(context.Background(),
		`SELECT output FROM live_response_commands WHERE id=$1::uuid`, cmdID).Scan(&out); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if out != "first" {
		t.Errorf("output = %q, want %q — the recorded outcome was replaced", out, "first")
	}
}

// TestAMalformedCommandIDIsARequestError. A non-uuid reaches Postgres as 22P02
// and comes back as a 500, which reads as a server fault for a bad request.
func TestAMalformedCommandIDIsARequestError(t *testing.T) {
	pool := lrCmdPool(t)
	h := handlers.NewLiveResponseCmdHandler(store.NewCmdQueueStore(pool))

	if code, body := postResult(t, h, "not-a-uuid", `{"status":"completed"}`); code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (body: %s)", code, body)
	}
}

// TestAResultForAnUnknownCommandIsNotSuccess. Nothing was updated, so answering
// 200 tells the agent its result was recorded when no such command exists.
func TestAResultForAnUnknownCommandIsNotSuccess(t *testing.T) {
	pool := lrCmdPool(t)
	h := handlers.NewLiveResponseCmdHandler(store.NewCmdQueueStore(pool))

	code, body := postResult(t, h, uuid.NewString(), `{"status":"completed","output":"x"}`)
	if code == http.StatusOK {
		t.Errorf("status = 200 for a command that does not exist (body: %s)", body)
	}
}
