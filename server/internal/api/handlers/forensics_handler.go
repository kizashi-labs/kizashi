package handlers

import (
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ForensicsHandler manages forensics job creation, tracking, and artifact retrieval.
type ForensicsHandler struct {
	pool     *pgxpool.Pool
	natsConn interface{ Publish(string, []byte) error }
}

// NewForensicsHandler creates a new ForensicsHandler.
func NewForensicsHandler(pool *pgxpool.Pool, nc interface{ Publish(string, []byte) error }) *ForensicsHandler {
	return &ForensicsHandler{pool: pool, natsConn: nc}
}

// ForensicsJob represents a forensics collection task.
type ForensicsJob struct {
	ID        string    `json:"id"`
	AgentID   string    `json:"agent_id"`
	Type      string    `json:"type"` // "memory_dump" | "process_list" | "artifact_collect"
	ProcessID int       `json:"process_id,omitempty"`
	Status    string    `json:"status"` // "pending" | "running" | "done" | "failed"
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by"`
}

// CreateJob handles POST /api/v1/forensics/jobs
// Body: {"agent_id":"...","type":"memory_dump","process_id":1234}
func (h *ForensicsHandler) CreateJob(c *gin.Context) {
	var req struct {
		AgentID   string `json:"agent_id" binding:"required"`
		Type      string `json:"type" binding:"required"`
		ProcessID int    `json:"process_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate job type
	switch req.Type {
	case "memory_dump", "process_list", "artifact_collect":
		// valid
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "無効なジョブタイプです。memory_dump, process_list, artifact_collect のいずれかを指定してください"})
		return
	}

	userID, _ := c.Get("user_id")
	userIDStr, _ := userID.(string)
	jobID := fmt.Sprintf("fj-%d", time.Now().UnixNano())

	_, err := h.pool.Exec(c.Request.Context(),
		`INSERT INTO forensics_jobs (id, agent_id, type, process_id, status, created_by, created_at)
		 VALUES ($1,$2,$3,$4,'pending',$5,NOW())`,
		jobID, req.AgentID, req.Type, req.ProcessID, userIDStr,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ジョブの作成に失敗しました"})
		return
	}

	// Notify agent via NATS
	if h.natsConn != nil {
		msg := fmt.Sprintf(`{"job_id":%q,"type":%q,"process_id":%d}`, jobID, req.Type, req.ProcessID)
		subject := fmt.Sprintf("agents.forensics.%s", req.AgentID)
		if err := h.natsConn.Publish(subject, []byte(msg)); err != nil {
			slog.Warn("NATS publish failed", "subject", subject, "error", err)
		}
	}

	c.JSON(http.StatusCreated, gin.H{"job_id": jobID, "status": "pending"})
}

// ListJobs handles GET /api/v1/forensics/jobs
// Optional query param: agent_id to filter by agent.
func (h *ForensicsHandler) ListJobs(c *gin.Context) {
	agentID := c.Query("agent_id")

	var (
		query string
		args  []interface{}
	)
	if agentID != "" {
		query = `SELECT id, agent_id, type, process_id, status, created_by, created_at
			 FROM forensics_jobs WHERE agent_id=$1 ORDER BY created_at DESC LIMIT 100`
		args = []interface{}{agentID}
	} else {
		query = `SELECT id, agent_id, type, process_id, status, created_by, created_at
			 FROM forensics_jobs ORDER BY created_at DESC LIMIT 100`
		args = []interface{}{}
	}

	rows, err := h.pool.Query(c.Request.Context(), query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "クエリに失敗しました"})
		return
	}
	defer rows.Close()

	jobs := make([]ForensicsJob, 0)
	for rows.Next() {
		var j ForensicsJob
		if scanErr := rows.Scan(&j.ID, &j.AgentID, &j.Type, &j.ProcessID, &j.Status, &j.CreatedBy, &j.CreatedAt); scanErr != nil {
			continue
		}
		jobs = append(jobs, j)
	}
	if err := rows.Err(); err != nil {
		slog.Error("rows.Err: 結果の読み出しが途中で失敗しました", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "クエリに失敗しました"})
		return
	}

	c.JSON(http.StatusOK, jobs)
}

// GetJob handles GET /api/v1/forensics/jobs/:id
func (h *ForensicsHandler) GetJob(c *gin.Context) {
	id := c.Param("id")
	var j ForensicsJob
	err := h.pool.QueryRow(c.Request.Context(),
		`SELECT id, agent_id, type, process_id, status, created_by, created_at
		 FROM forensics_jobs WHERE id=$1`, id,
	).Scan(&j.ID, &j.AgentID, &j.Type, &j.ProcessID, &j.Status, &j.CreatedBy, &j.CreatedAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "ジョブが見つかりません"})
		return
	}
	c.JSON(http.StatusOK, j)
}

// DownloadArtifact handles GET /api/v1/forensics/jobs/:id/download
// Returns the raw artifact bytes as an octet-stream attachment.
func (h *ForensicsHandler) DownloadArtifact(c *gin.Context) {
	id := c.Param("id")

	var artifact []byte
	var agentID, jobType string
	err := h.pool.QueryRow(c.Request.Context(),
		`SELECT agent_id, type, artifact_data FROM forensics_jobs WHERE id=$1 AND status='done'`, id,
	).Scan(&agentID, &jobType, &artifact)
	if err != nil || artifact == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "アーティファクトが利用できません"})
		return
	}

	agentPrefix := agentID
	if len(agentPrefix) > 8 {
		agentPrefix = agentPrefix[:8]
	}
	filename := fmt.Sprintf("forensics_%s_%s_%d.bin", agentPrefix, jobType, time.Now().Unix())
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	c.Data(http.StatusOK, "application/octet-stream", artifact)
}

// SubmitResult handles POST /api/v1/forensics/jobs/:id/result
// Called by the agent (via direct POST or NATS callback) to store collected data.
// DeleteJob removes a forensics job.
// DELETE /api/v1/forensics/jobs/:id
func (h *ForensicsHandler) DeleteJob(c *gin.Context) {
	id := c.Param("id")
	_, err := h.pool.Exec(c.Request.Context(), `DELETE FROM forensics_jobs WHERE id=$1`, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ジョブの削除に失敗しました"})
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *ForensicsHandler) SubmitResult(c *gin.Context) {
	id := c.Param("id")
	data, err := c.GetRawData()
	if err != nil || len(data) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "データがありません"})
		return
	}

	_, err = h.pool.Exec(c.Request.Context(),
		`UPDATE forensics_jobs SET status='done', artifact_data=$1, completed_at=NOW() WHERE id=$2`,
		data, id,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "結果の保存に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "done"})
}
