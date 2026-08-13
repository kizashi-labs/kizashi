package handlers

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/edr-platform/server/internal/store"
)

type QuarantineActionsHandler struct {
	pool      *pgxpool.Pool
	commander *store.CommandStore
}

func NewQuarantineActionsHandler(pool *pgxpool.Pool) *QuarantineActionsHandler {
	return &QuarantineActionsHandler{pool: pool}
}

// NewQuarantineActionsHandlerWithCommander creates a handler with NATS command dispatch.
func NewQuarantineActionsHandlerWithCommander(pool *pgxpool.Pool, commander *store.CommandStore) *QuarantineActionsHandler {
	return &QuarantineActionsHandler{pool: pool, commander: commander}
}

func (h *QuarantineActionsHandler) List(c *gin.Context) {
	rows, err := h.pool.Query(c.Request.Context(), `
		SELECT q.id, q.agent_id, a.hostname, q.status, q.reason, q.network_isolated,
		       q.process_killed, q.started_at, q.released_at, q.created_at
		FROM quarantine_actions q
		LEFT JOIN agents a ON a.id = q.agent_id
		ORDER BY q.created_at DESC LIMIT 100
	`)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"quarantines": []any{}})
		return
	}
	defer rows.Close()

	type Item struct {
		ID              string  `json:"id"`
		AgentID         string  `json:"agent_id"`
		Hostname        string  `json:"hostname"`
		Status          string  `json:"status"`
		Reason          string  `json:"reason"`
		NetworkIsolated bool    `json:"network_isolated"`
		ProcessKilled   bool    `json:"process_killed"`
		StartedAt       *string `json:"started_at"`
		ReleasedAt      *string `json:"released_at"`
		CreatedAt       string  `json:"created_at"`
	}

	var list []Item
	for rows.Next() {
		var it Item
		var startedAt, releasedAt *time.Time
		var createdAt time.Time
		if err := rows.Scan(&it.ID, &it.AgentID, &it.Hostname, &it.Status, &it.Reason,
			&it.NetworkIsolated, &it.ProcessKilled, &startedAt, &releasedAt, &createdAt); err != nil {
			continue
		}
		it.CreatedAt = createdAt.UTC().Format(time.RFC3339)
		if startedAt != nil {
			s := startedAt.UTC().Format(time.RFC3339)
			it.StartedAt = &s
		}
		if releasedAt != nil {
			r := releasedAt.UTC().Format(time.RFC3339)
			it.ReleasedAt = &r
		}
		list = append(list, it)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}
	if list == nil {
		list = []Item{}
	}
	c.JSON(http.StatusOK, gin.H{"quarantines": list})
}

func (h *QuarantineActionsHandler) Create(c *gin.Context) {
	var req struct {
		AgentID         string `json:"agent_id" binding:"required"`
		Reason          string `json:"reason"`
		NetworkIsolated bool   `json:"network_isolated"`
		ProcessKilled   bool   `json:"process_killed"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	now := time.Now()
	var id string
	err := h.pool.QueryRow(c.Request.Context(), `
		INSERT INTO quarantine_actions (agent_id, reason, network_isolated, process_killed, status, started_at)
		VALUES ($1, $2, $3, $4, 'active', $5)
		RETURNING id
	`, req.AgentID, req.Reason, req.NetworkIsolated, req.ProcessKilled, now).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}

	// Dispatch real command to agent via NATS if commander is available.
	if h.commander != nil && req.NetworkIsolated {
		if err := h.commander.IsolateEndpoint(c.Request.Context(), req.AgentID, req.Reason, "", ""); err != nil {
			// Log but do not fail the HTTP response; the DB record is authoritative.
			_ = err
		}
	}

	c.JSON(http.StatusCreated, gin.H{"id": id, "status": "active"})
}

func (h *QuarantineActionsHandler) Release(c *gin.Context) {
	id := c.Param("id")
	now := time.Now()

	// Look up the agent_id so we can send the unisolate command.
	var agentID string
	_ = h.pool.QueryRow(c.Request.Context(),
		`SELECT agent_id FROM quarantine_actions WHERE id = $1`, id).Scan(&agentID)

	_, err := h.pool.Exec(c.Request.Context(),
		`UPDATE quarantine_actions SET status='released', released_at=$1, updated_at=$1 WHERE id=$2`,
		now, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}

	// Send unisolate command to agent via NATS.
	if h.commander != nil && agentID != "" {
		if err := h.commander.UnisolateEndpoint(c.Request.Context(), agentID, "quarantine released", ""); err != nil {
			_ = err
		}
	}

	c.JSON(http.StatusOK, gin.H{"status": "released"})
}

func (h *QuarantineActionsHandler) Stats(c *gin.Context) {
	var total, active, released int
	if err := h.pool.QueryRow(c.Request.Context(), `SELECT COUNT(*), COUNT(*) FILTER (WHERE status='active'), COUNT(*) FILTER (WHERE status='released') FROM quarantine_actions`).Scan(&total, &active, &released); err != nil {
		slog.Warn("quarantine actions: 集計クエリに失敗しました", "error", err)
	}
	c.JSON(http.StatusOK, gin.H{"total": total, "active": active, "released": released})
}
