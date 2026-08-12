package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

// AutoRemediationHandler manages agent auto-remediation actions.
type AutoRemediationHandler struct {
	pool *pgxpool.Pool
	nc   *nats.Conn
}

// NewAutoRemediationHandler creates a new AutoRemediationHandler.
func NewAutoRemediationHandler(pool *pgxpool.Pool, nc *nats.Conn) *AutoRemediationHandler {
	return &AutoRemediationHandler{pool: pool, nc: nc}
}

// RemediationAction represents a single remediation action dispatched to an agent.
type RemediationAction struct {
	ID         string    `json:"id"`
	AgentID    string    `json:"agent_id"`
	ActionType string    `json:"action_type"`
	Target     string    `json:"target"`
	Reason     string    `json:"reason"`
	Status     string    `json:"status"`
	ExecutedAt time.Time `json:"executed_at"`
	Result     string    `json:"result"`
	ExecutedBy *string   `json:"executed_by,omitempty"`
}

var validActionTypes = map[string]bool{
	"kill_process":      true,
	"block_ip":          true,
	"delete_file":       true,
	"isolate_agent":     true,
	"collect_forensics": true,
}

const createRemediationTable = `
CREATE TABLE IF NOT EXISTS remediation_actions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id UUID NOT NULL,
  action_type TEXT NOT NULL,
  target TEXT NOT NULL,
  reason TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'dispatched',
  result TEXT NOT NULL DEFAULT '',
  executed_by UUID,
  executed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);`

func (h *AutoRemediationHandler) ensureTable(ctx context.Context) error {
	_, err := h.pool.Exec(ctx, createRemediationTable)
	return err
}

// ExecuteAction dispatches a remediation action to an agent.
// POST /agents/:id/remediate
func (h *AutoRemediationHandler) ExecuteAction(c *gin.Context) {
	agentID := c.Param("id")
	var req struct {
		ActionType string `json:"action_type" binding:"required"`
		Target     string `json:"target" binding:"required"`
		Reason     string `json:"reason"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "無効なリクエストです: " + err.Error()})
		return
	}

	if !validActionTypes[req.ActionType] {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("無効なアクションタイプです: %s。有効な値: kill_process, block_ip, delete_file, isolate_agent, collect_forensics", req.ActionType),
		})
		return
	}

	ctx := c.Request.Context()
	if err := h.ensureTable(ctx); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "テーブルの初期化に失敗しました"})
		return
	}

	userID, _ := c.Get("user_id")
	userIDStr, _ := userID.(string)

	var actionID string
	err := h.pool.QueryRow(ctx,
		`INSERT INTO remediation_actions (agent_id, action_type, target, reason, status, executed_by)
		 VALUES ($1, $2, $3, $4, 'dispatched', $5::uuid)
		 RETURNING id`,
		agentID, req.ActionType, req.Target, req.Reason, nilIfEmpty(userIDStr),
	).Scan(&actionID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}

	// Publish NATS message to the agent
	payload := map[string]interface{}{
		"action_id":   actionID,
		"agent_id":    agentID,
		"action_type": req.ActionType,
		"target":      req.Target,
		"reason":      req.Reason,
		"executed_by": userIDStr,
	}
	if h.nc != nil {
		data, _ := json.Marshal(payload)
		if err := h.nc.Publish("agent.remediate", data); err != nil {
			slog.Warn("remediation publish failed", "error", err)
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"action_id": actionID,
		"status":    "dispatched",
		"message":   "エージェントにコマンドを送信しました",
	})
}

// GetActionHistory returns remediation history for a specific agent.
// GET /agents/:id/remediation-history
func (h *AutoRemediationHandler) GetActionHistory(c *gin.Context) {
	agentID := c.Param("id")
	ctx := c.Request.Context()

	if err := h.ensureTable(ctx); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "テーブルの初期化に失敗しました"})
		return
	}

	rows, err := h.pool.Query(ctx,
		`SELECT id, agent_id, action_type, target, reason, status, result, executed_at
		 FROM remediation_actions
		 WHERE agent_id = $1::uuid
		 ORDER BY executed_at DESC
		 LIMIT 100`,
		agentID,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	defer rows.Close()

	var actions []RemediationAction
	for rows.Next() {
		var a RemediationAction
		if err := rows.Scan(&a.ID, &a.AgentID, &a.ActionType, &a.Target, &a.Reason, &a.Status, &a.Result, &a.ExecutedAt); err != nil {
			continue
		}
		actions = append(actions, a)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}
	if actions == nil {
		actions = []RemediationAction{}
	}
	c.JSON(http.StatusOK, gin.H{"actions": actions, "total": len(actions)})
}

// BulkRemediate dispatches remediation actions to multiple agents.
// POST /agents/bulk-remediate
func (h *AutoRemediationHandler) BulkRemediate(c *gin.Context) {
	var req struct {
		AgentIDs   []string `json:"agent_ids" binding:"required"`
		ActionType string   `json:"action_type" binding:"required"`
		Target     string   `json:"target" binding:"required"`
		Reason     string   `json:"reason"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "無効なリクエストです: " + err.Error()})
		return
	}

	if !validActionTypes[req.ActionType] {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("無効なアクションタイプです: %s", req.ActionType),
		})
		return
	}

	ctx := c.Request.Context()
	if err := h.ensureTable(ctx); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "テーブルの初期化に失敗しました"})
		return
	}

	userID, _ := c.Get("user_id")
	userIDStr, _ := userID.(string)

	type result struct {
		AgentID  string `json:"agent_id"`
		ActionID string `json:"action_id,omitempty"`
		Status   string `json:"status"`
		Error    string `json:"error,omitempty"`
	}

	results := make([]result, 0, len(req.AgentIDs))
	for _, agentID := range req.AgentIDs {
		var actionID string
		err := h.pool.QueryRow(ctx,
			`INSERT INTO remediation_actions (agent_id, action_type, target, reason, status, executed_by)
			 VALUES ($1, $2, $3, $4, 'dispatched', $5::uuid)
			 RETURNING id`,
			agentID, req.ActionType, req.Target, req.Reason, nilIfEmpty(userIDStr),
		).Scan(&actionID)
		if err != nil {
			results = append(results, result{AgentID: agentID, Status: "failed", Error: err.Error()})
			continue
		}

		if h.nc != nil {
			payload := map[string]interface{}{
				"action_id":   actionID,
				"agent_id":    agentID,
				"action_type": req.ActionType,
				"target":      req.Target,
				"reason":      req.Reason,
				"executed_by": userIDStr,
			}
			data, _ := json.Marshal(payload)
			if err := h.nc.Publish("agent.remediate", data); err != nil {
				slog.Warn("bulk remediation publish failed", "agent_id", agentID, "error", err)
			}
		}

		results = append(results, result{AgentID: agentID, ActionID: actionID, Status: "dispatched"})
	}

	c.JSON(http.StatusOK, gin.H{"results": results, "total": len(results)})
}

// GetStats returns remediation statistics.
// GET /remediation/stats
func (h *AutoRemediationHandler) GetStats(c *gin.Context) {
	ctx := c.Request.Context()

	if err := h.ensureTable(ctx); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "テーブルの初期化に失敗しました"})
		return
	}

	var actionsToday int
	_ = h.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM remediation_actions WHERE executed_at >= NOW() - INTERVAL '24 hours'`,
	).Scan(&actionsToday)

	rows, err := h.pool.Query(ctx,
		`SELECT action_type, COUNT(*) FROM remediation_actions GROUP BY action_type`,
	)
	byType := map[string]int{}
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var actionType string
			var count int
			if err := rows.Scan(&actionType, &count); err == nil {
				byType[actionType] = count
			}
		}
		if err := rows.Err(); err != nil {
			slog.Warn("row iteration error", "error", err)
		}
	}

	var totalSuccess, total int
	_ = h.pool.QueryRow(ctx,
		`SELECT COUNT(*) FILTER (WHERE status = 'success'), COUNT(*) FROM remediation_actions`,
	).Scan(&totalSuccess, &total)

	var successRate float64
	if total > 0 {
		successRate = float64(totalSuccess) / float64(total) * 100.0
	}

	c.JSON(http.StatusOK, gin.H{
		"actions_today": actionsToday,
		"by_type":       byType,
		"success_rate":  successRate,
		"total":         total,
	})
}
