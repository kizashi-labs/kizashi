package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/edr-platform/server/internal/store"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// LiveResponseCmdHandler handles the live response command queue API.
// It is a separate type from LiveResponseHandler (which manages terminal sessions).
type LiveResponseCmdHandler struct {
	store *store.CmdQueueStore
}

// NewLiveResponseCmdHandler creates a new LiveResponseCmdHandler.
func NewLiveResponseCmdHandler(s *store.CmdQueueStore) *LiveResponseCmdHandler {
	return &LiveResponseCmdHandler{store: s}
}

var validCmdQueueTypes = map[string]bool{
	"shell": true, "file_list": true, "file_get": true, "file_put": true,
	"process_list": true, "process_kill": true, "network_list": true, "reg_query": true,
}

// CreateCommand handles POST /api/v1/agents/:agent_id/commands
func (h *LiveResponseCmdHandler) CreateCommand(c *gin.Context) {
	agentID := c.Param("id")
	var req struct {
		CommandType string          `json:"command_type" binding:"required"`
		Command     string          `json:"command" binding:"required"`
		Args        json.RawMessage `json:"args"`
		SessionID   *string         `json:"session_id,omitempty"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if !validCmdQueueTypes[req.CommandType] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "無効なコマンドタイプです"})
		return
	}
	if strings.TrimSpace(req.Command) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "commandは必須です"})
		return
	}
	userID := c.GetString("user_id")
	var createdBy *string
	if userID != "" {
		createdBy = &userID
	}
	cmd, err := h.store.Create(c.Request.Context(), store.CreateQueuedCommandInput{
		AgentID:     agentID,
		SessionID:   req.SessionID,
		CommandType: req.CommandType,
		Command:     req.Command,
		Args:        req.Args,
		CreatedBy:   createdBy,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "コマンドの作成に失敗しました"})
		return
	}
	c.JSON(http.StatusCreated, cmd)
}

// GetCommand handles GET /api/v1/agents/:agent_id/commands/:cmd_id
func (h *LiveResponseCmdHandler) GetCommand(c *gin.Context) {
	cmdID := c.Param("cmd_id")
	cmd, err := h.store.Get(c.Request.Context(), cmdID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "コマンドが見つかりません"})
		return
	}
	c.JSON(http.StatusOK, cmd)
}

// ListCommands handles GET /api/v1/agents/:agent_id/commands
func (h *LiveResponseCmdHandler) ListCommands(c *gin.Context) {
	agentID := c.Param("id")
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	cmds, err := h.store.ListByAgent(c.Request.Context(), agentID, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "コマンド一覧の取得に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"commands": cmds})
}

// PollCommands handles GET /api/v1/agent/commands/poll (called by agent)
func (h *LiveResponseCmdHandler) PollCommands(c *gin.Context) {
	agentID := c.GetString("agent_id")
	if agentID == "" {
		agentID = c.Query("agent_id")
	}
	if agentID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "agent_idは必須です"})
		return
	}
	cmds, err := h.store.PendingForAgent(c.Request.Context(), agentID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "コマンドの取得に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"commands": cmds})
}

// SubmitResult handles POST /api/v1/agent/commands/:cmd_id/result (called by agent)
func (h *LiveResponseCmdHandler) SubmitResult(c *gin.Context) {
	cmdID := c.Param("cmd_id")
	var req struct {
		Status   string `json:"status"`
		Output   string `json:"output"`
		ExitCode *int   `json:"exit_code,omitempty"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Status == "" {
		req.Status = "completed"
	}
	// A malformed id would reach Postgres as an invalid uuid (22P02) and come
	// back as a 500, which reads as a server fault for what is a bad request.
	if _, err := uuid.Parse(cmdID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cmd_idの形式が不正です"})
		return
	}
	applied, err := h.store.UpdateResult(c.Request.Context(), cmdID, req.Status, req.Output, req.ExitCode)
	if errors.Is(err, store.ErrUnknownResultStatus) {
		// The caller sent a word this system does not use. Saying so beats the
		// 500 it used to get from the CHECK constraint, which named the
		// constraint and not the field.
		c.JSON(http.StatusBadRequest, gin.H{"error": "statusの値が不正です: " + req.Status})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "結果の更新に失敗しました"})
		return
	}
	if !applied {
		// The command is gone, or already finished — timed out by the sweeper,
		// cancelled, or answered by an earlier delivery of this same result.
		// Overwriting it would replace a recorded outcome with a later guess.
		c.JSON(http.StatusConflict, gin.H{"error": "コマンドは既に終了しているため結果を受け付けられません"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "結果を受け付けました"})
}

// CancelCommand handles DELETE /api/v1/agents/:agent_id/commands/:cmd_id
func (h *LiveResponseCmdHandler) CancelCommand(c *gin.Context) {
	cmdID := c.Param("cmd_id")
	if err := h.store.Cancel(c.Request.Context(), cmdID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "コマンドのキャンセルに失敗しました: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "コマンドをキャンセルしました"})
}
