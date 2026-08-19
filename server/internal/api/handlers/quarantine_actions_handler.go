package handlers

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/edr-platform/server/internal/isolation"
)

type QuarantineActionsHandler struct {
	pool     *pgxpool.Pool
	isolator endpointIsolator
}

func NewQuarantineActionsHandler(pool *pgxpool.Pool) *QuarantineActionsHandler {
	return &QuarantineActionsHandler{pool: pool}
}

// NewQuarantineActionsHandlerWithIsolator creates a handler that can actually
// take endpoints off the network.
//
// この経路は以前 CommandStore を直接叩いていて、response_actions に一行も
// 残さず、安全弁も通らなかった。quarantine_actions テーブルに行が増えるだけで、
// 対応履歴からは存在しない隔離になっていた。
func NewQuarantineActionsHandlerWithIsolator(pool *pgxpool.Pool, isolator endpointIsolator) *QuarantineActionsHandler {
	return &QuarantineActionsHandler{pool: pool, isolator: isolator}
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
		ReadFailure(c, err, gin.H{"quarantines": []any{}})
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
		slog.Error("rows.Err: 結果の読み出しが途中で失敗しました", "error", err)
		ReadFailure(c, err, gin.H{"quarantines": []any{}})
		return
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

	// Dispatch through the gatekeeper so the isolation is recorded and rate-limited.
	if h.isolator != nil && req.NetworkIsolated {
		res, err := h.isolator.Isolate(c.Request.Context(), isolation.Request{
			AgentID: req.AgentID,
			Reason:  req.Reason,
			Origin:  isolation.OriginQuarantineAction,
			Label:   "隔離アクション",
		})
		if err != nil {
			slog.Error("隔離アクションの送信に失敗しました", "agent", req.AgentID, "error", err)
		} else if !res.Outcome.Executed() {
			slog.Warn("隔離アクションは実行されませんでした",
				"agent", req.AgentID, "結果", string(res.Outcome), "理由", res.Reason)
		}
	}

	c.JSON(http.StatusCreated, gin.H{"id": id, "status": "active"})
}

func (h *QuarantineActionsHandler) Release(c *gin.Context) {
	id := c.Param("id")
	now := time.Now()

	// Look up the agent_id so we can send the unisolate command.
	var agentID string
	if !ReadOK(c, h.pool.QueryRow(c.Request.Context(),
		`SELECT agent_id FROM quarantine_actions WHERE id = $1`, id).Scan(&agentID)) {
		return
	}

	_, err := h.pool.Exec(c.Request.Context(),
		`UPDATE quarantine_actions SET status='released', released_at=$1, updated_at=$1 WHERE id=$2`,
		now, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}

	// Send unisolate command through the gatekeeper.
	if h.isolator != nil && agentID != "" {
		if _, err := h.isolator.Unisolate(c.Request.Context(), isolation.Request{
			AgentID: agentID,
			Reason:  "quarantine released",
			Origin:  isolation.OriginQuarantineAction,
			Label:   "隔離アクション解除",
		}); err != nil {
			slog.Error("隔離解除の送信に失敗しました", "agent", agentID, "error", err)
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
