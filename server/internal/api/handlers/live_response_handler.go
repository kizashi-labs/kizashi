package handlers

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/edr-platform/server/internal/store"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

// LiveResponseCommander dispatches commands to agents.
type LiveResponseCommander interface {
	EnqueueLiveResponseStart(agentID, sessionID, token, callbackURL string) error
}

// LiveResponseHandler handles live response terminal sessions.
type LiveResponseHandler struct {
	Store     *store.LiveResponseStore
	Pool      *pgxpool.Pool
	NC        *nats.Conn
	Commander LiveResponseCommander
	BaseURL   string
}

// NewLiveResponseHandler creates a new LiveResponseHandler.
func NewLiveResponseHandler(
	s *store.LiveResponseStore,
	pool *pgxpool.Pool,
	nc *nats.Conn,
	commander LiveResponseCommander,
	baseURL string,
) *LiveResponseHandler {
	return &LiveResponseHandler{
		Store:     s,
		Pool:      pool,
		NC:        nc,
		Commander: commander,
		BaseURL:   baseURL,
	}
}

// extractEmail attempts to pull the user's email from the gin context JWT claims.
func extractEmail(c *gin.Context) string {
	userVal, ok := c.Get("user")
	if !ok {
		return ""
	}
	if m, ok := userVal.(map[string]interface{}); ok {
		if email, ok := m["email"].(string); ok && email != "" {
			return email
		}
	}
	// Support auth.Claims struct via duck-typed interface
	type emailer interface{ GetEmail() string }
	if e, ok := userVal.(emailer); ok {
		return e.GetEmail()
	}
	return ""
}

// CreateSession starts a new live response session for an agent.
// POST /api/v1/agents/:id/live-response/sessions
func (h *LiveResponseHandler) CreateSession(c *gin.Context) {
	agentID := c.Param("id")

	startedBy := extractEmail(c)
	if startedBy == "" {
		startedBy = "system"
	}

	token := uuid.New().String()

	session, err := h.Store.CreateSession(c.Request.Context(), agentID, token, startedBy)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}

	// Dispatch start command to agent
	if h.Commander != nil {
		callbackURL := fmt.Sprintf("%s/api/v1", h.BaseURL)
		if err := h.Commander.EnqueueLiveResponseStart(agentID, session.ID, token, callbackURL); err != nil {
			slog.Warn("live response start command dispatch failed", "agent", agentID, "error", err)
		}
	}

	c.JSON(http.StatusCreated, session)
}

// ListSessions returns all sessions for an agent.
// GET /api/v1/agents/:id/live-response/sessions
func (h *LiveResponseHandler) ListSessions(c *gin.Context) {
	agentID := c.Param("id")
	sessions, err := h.Store.ListSessions(c.Request.Context(), agentID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "セッション一覧の取得に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": sessions})
}

// CloseSession terminates an active live response session.
// DELETE /api/v1/agents/:id/live-response/sessions/:sid
func (h *LiveResponseHandler) CloseSession(c *gin.Context) {
	sessionID := c.Param("sid")
	if err := h.Store.CloseSession(c.Request.Context(), sessionID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "セッションのクローズに失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "セッションを終了しました"})
}

// ExecCommand queues a shell command for execution on the agent.
// POST /api/v1/agents/:id/live-response/sessions/:sid/exec
func (h *LiveResponseHandler) ExecCommand(c *gin.Context) {
	sessionID := c.Param("sid")

	var req struct {
		Command string `json:"command" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "commandフィールドが必要です"})
		return
	}

	submittedBy := extractEmail(c)
	if submittedBy == "" {
		submittedBy = "analyst"
	}

	cmd, err := h.Store.EnqueueCommand(c.Request.Context(), sessionID, req.Command, submittedBy)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "コマンドのキューへの追加に失敗しました"})
		return
	}

	c.JSON(http.StatusCreated, cmd)
}

// GetCommands returns all commands for a session as JSON (for polling).
// GET /api/v1/agents/:id/live-response/sessions/:sid/commands
func (h *LiveResponseHandler) GetCommands(c *gin.Context) {
	sessionID := c.Param("sid")
	cmds, err := h.Store.ListCommands(c.Request.Context(), sessionID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "コマンド一覧の取得に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": cmds})
}

// StreamOutput streams command output for a session via SSE.
// GET /api/v1/agents/:id/live-response/sessions/:sid/stream
func (h *LiveResponseHandler) StreamOutput(c *gin.Context) {
	sessionID := c.Param("sid")

	flusher, ok := c.Writer.(http.Flusher)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "streaming not supported"})
		return
	}

	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	// CORS is handled by the router-level middleware; do not override here.

	// Send existing commands first (for reconnect recovery)
	existing, _ := h.Store.ListCommands(c.Request.Context(), sessionID)
	for _, cmd := range existing {
		data, _ := json.Marshal(map[string]interface{}{
			"type":       "output",
			"command_id": cmd.ID,
			"input":      cmd.Input,
			"output":     cmd.Output,
			"exit_code":  cmd.ExitCode,
			"status":     cmd.Status,
			"timestamp":  cmd.SubmittedAt,
		})
		fmt.Fprintf(c.Writer, "data: %s\n\n", data)
	}
	flusher.Flush()

	if h.NC == nil {
		// No NATS — hold connection open with heartbeat only
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				fmt.Fprintf(c.Writer, ": heartbeat\n\n")
				flusher.Flush()
			case <-c.Request.Context().Done():
				return
			}
		}
	}

	// Subscribe to NATS for real-time output
	msgCh := make(chan []byte, 64)
	sub, err := h.NC.Subscribe(fmt.Sprintf("live.response.output.%s", sessionID), func(msg *nats.Msg) {
		select {
		case msgCh <- msg.Data:
		default:
		}
	})
	if err != nil {
		slog.Warn("live response NATS subscribe failed", "session", sessionID, "error", err)
	} else {
		defer sub.Unsubscribe()
	}

	heartbeat := time.NewTicker(30 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case msg := <-msgCh:
			fmt.Fprintf(c.Writer, "data: %s\n\n", msg)
			flusher.Flush()
		case <-heartbeat.C:
			fmt.Fprintf(c.Writer, ": heartbeat\n\n")
			flusher.Flush()
		case <-c.Request.Context().Done():
			return
		}
	}
}

// AgentPoll is called by the agent to fetch pending commands.
// GET /api/v1/live-response/poll?token=XXX  (no JWT auth required)
func (h *LiveResponseHandler) AgentPoll(c *gin.Context) {
	token := c.Query("token")
	if token == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "token required"})
		return
	}

	session, err := h.Store.GetSessionByToken(c.Request.Context(), token)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired session"})
		return
	}

	h.Store.TouchSession(c.Request.Context(), token)

	cmds, err := h.Store.DequeuePendingCommands(c.Request.Context(), session.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "command fetch failed"})
		return
	}

	type cmdItem struct {
		ID    string `json:"id"`
		Input string `json:"input"`
	}
	items := make([]cmdItem, len(cmds))
	for i, cmd := range cmds {
		items[i] = cmdItem{ID: cmd.ID, Input: cmd.Input}
	}

	c.JSON(http.StatusOK, gin.H{"commands": items, "session_id": session.ID})
}

// AgentOutput is called by the agent to submit command output.
// POST /api/v1/live-response/output?token=XXX  (no JWT auth required)
func (h *LiveResponseHandler) AgentOutput(c *gin.Context) {
	token := c.Query("token")
	if token == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "token required"})
		return
	}

	session, err := h.Store.GetSessionByToken(c.Request.Context(), token)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired session"})
		return
	}

	var req struct {
		CommandID string `json:"command_id" binding:"required"`
		Input     string `json:"input"`
		Output    string `json:"output"`
		ExitCode  int    `json:"exit_code"`
		HasError  bool   `json:"error"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}

	if err := h.Store.CompleteCommand(c.Request.Context(), req.CommandID, req.Output, req.ExitCode, req.HasError); err != nil {
		slog.Warn("live response: CompleteCommand failed", "cmd", req.CommandID, "error", err)
	}

	h.Store.TouchSession(c.Request.Context(), token)

	// Publish to NATS so SSE clients receive real-time update
	if h.NC != nil {
		msg, _ := json.Marshal(map[string]interface{}{
			"type":       "output",
			"command_id": req.CommandID,
			"input":      req.Input,
			"output":     req.Output,
			"exit_code":  req.ExitCode,
			"error":      req.HasError,
			"timestamp":  time.Now(),
		})
		subject := fmt.Sprintf("live.response.output.%s", session.ID)
		if pubErr := h.NC.Publish(subject, msg); pubErr != nil {
			slog.Warn("live response NATS publish failed", "error", pubErr)
		}
	}

	c.JSON(http.StatusOK, gin.H{"ok": true})
}
