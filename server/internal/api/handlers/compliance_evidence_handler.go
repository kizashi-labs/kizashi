package handlers

import (
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ComplianceEvidenceHandler manages compliance evidence collection tasks and items.
type ComplianceEvidenceHandler struct {
	pool *pgxpool.Pool
}

func NewComplianceEvidenceHandler(pool *pgxpool.Pool) *ComplianceEvidenceHandler {
	return &ComplianceEvidenceHandler{pool: pool}
}

// ListTasks GET /tasks — filter by framework
func (h *ComplianceEvidenceHandler) ListTasks(c *gin.Context) {
	framework := c.Query("framework")

	query := `
		SELECT id, name, framework, control_id, COALESCE(description,''),
		       collection_method, COALESCE(schedule,''), is_active, last_collected, created_at
		FROM compliance_evidence_tasks
		WHERE 1=1`
	args := []interface{}{}
	argIdx := 1

	if framework != "" {
		query += fmt.Sprintf(" AND framework=$%d", argIdx)
		args = append(args, framework)
		argIdx++
	}
	_ = argIdx
	query += " ORDER BY created_at DESC"

	rows, err := h.pool.Query(c.Request.Context(), query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	defer rows.Close()

	type Task struct {
		ID               string     `json:"id"`
		Name             string     `json:"name"`
		Framework        string     `json:"framework"`
		ControlID        string     `json:"control_id"`
		Description      string     `json:"description"`
		CollectionMethod string     `json:"collection_method"`
		Schedule         string     `json:"schedule"`
		IsActive         bool       `json:"is_active"`
		LastCollected    *time.Time `json:"last_collected"`
		CreatedAt        time.Time  `json:"created_at"`
	}

	var tasks []Task
	for rows.Next() {
		var t Task
		if err := rows.Scan(&t.ID, &t.Name, &t.Framework, &t.ControlID, &t.Description,
			&t.CollectionMethod, &t.Schedule, &t.IsActive, &t.LastCollected, &t.CreatedAt); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
			return
		}
		tasks = append(tasks, t)
	}
	if err := rows.Err(); err != nil {
		slog.Error("rows.Err: 結果の読み出しが途中で失敗しました", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if tasks == nil {
		tasks = []Task{}
	}
	c.JSON(http.StatusOK, gin.H{"tasks": tasks})
}

// CreateTask POST /tasks
func (h *ComplianceEvidenceHandler) CreateTask(c *gin.Context) {
	var body struct {
		Name             string `json:"name" binding:"required"`
		Framework        string `json:"framework" binding:"required"`
		ControlID        string `json:"control_id" binding:"required"`
		Description      string `json:"description"`
		CollectionMethod string `json:"collection_method" binding:"required"`
		Schedule         string `json:"schedule"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var id string
	err := h.pool.QueryRow(c.Request.Context(), `
		INSERT INTO compliance_evidence_tasks
		  (name, framework, control_id, description, collection_method, schedule)
		VALUES ($1, $2, $3, $4, $5, NULLIF($6,''))
		RETURNING id
	`, body.Name, body.Framework, body.ControlID, body.Description,
		body.CollectionMethod, body.Schedule).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id})
}

// UpdateTask PUT /tasks/:id
func (h *ComplianceEvidenceHandler) UpdateTask(c *gin.Context) {
	id := c.Param("id")
	var body struct {
		Name             string `json:"name"`
		Framework        string `json:"framework"`
		ControlID        string `json:"control_id"`
		Description      string `json:"description"`
		CollectionMethod string `json:"collection_method"`
		Schedule         string `json:"schedule"`
		IsActive         *bool  `json:"is_active"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	tag, err := h.pool.Exec(c.Request.Context(), `
		UPDATE compliance_evidence_tasks
		SET name=$1, framework=$2, control_id=$3, description=$4,
		    collection_method=$5, schedule=NULLIF($6,''),
		    is_active=COALESCE($7, is_active)
		WHERE id=$8
	`, body.Name, body.Framework, body.ControlID, body.Description,
		body.CollectionMethod, body.Schedule, body.IsActive, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "updated"})
}

// DeleteTask DELETE /tasks/:id
func (h *ComplianceEvidenceHandler) DeleteTask(c *gin.Context) {
	id := c.Param("id")
	tag, err := h.pool.Exec(c.Request.Context(), `DELETE FROM compliance_evidence_tasks WHERE id=$1`, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	c.Status(http.StatusNoContent)
}

// TriggerCollection POST /tasks/:id/collect — inserts a mock evidence item
func (h *ComplianceEvidenceHandler) TriggerCollection(c *gin.Context) {
	taskID := c.Param("id")
	ctx := c.Request.Context()

	// Fetch task details for framework/control_id
	var framework, controlID, taskName string
	err := h.pool.QueryRow(ctx, `
		SELECT framework, control_id, name FROM compliance_evidence_tasks WHERE id=$1
	`, taskID).Scan(&framework, &controlID, &taskName)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "task not found"})
		return
	}

	now := time.Now().UTC()
	content := fmt.Sprintf("自動収集されたスナップショット at %s", now.Format(time.RFC3339))
	itemName := fmt.Sprintf("Auto-collected: %s (%s)", taskName, now.Format("2006-01-02T15:04:05"))

	type EvidenceItem struct {
		ID           string    `json:"id"`
		TaskID       string    `json:"task_id"`
		Framework    string    `json:"framework"`
		ControlID    string    `json:"control_id"`
		Name         string    `json:"name"`
		EvidenceType string    `json:"evidence_type"`
		Content      string    `json:"content"`
		CollectedAt  time.Time `json:"collected_at"`
		CollectedBy  string    `json:"collected_by"`
		Status       string    `json:"status"`
	}

	var item EvidenceItem
	item.TaskID = taskID
	item.Framework = framework
	item.ControlID = controlID
	item.Name = itemName
	item.EvidenceType = "config_snapshot"
	item.Content = content
	item.CollectedAt = now
	item.CollectedBy = "system"
	item.Status = "pending_review"

	err = h.pool.QueryRow(ctx, `
		INSERT INTO compliance_evidence_items
		  (task_id, framework, control_id, name, evidence_type, content, collected_by, status)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id
	`, taskID, framework, controlID, itemName, "config_snapshot", content, "system", "pending_review").
		Scan(&item.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}

	// Update last_collected on the task
	if _, err := h.pool.Exec(ctx, `UPDATE compliance_evidence_tasks SET last_collected=NOW() WHERE id=$1`, taskID); !WriteOK(c, err) {
		return
	}

	c.JSON(http.StatusCreated, gin.H{"item": item})
}

// ListEvidence GET /evidence — filter by framework, control_id, status, task_id
func (h *ComplianceEvidenceHandler) ListEvidence(c *gin.Context) {
	framework := c.Query("framework")
	controlID := c.Query("control_id")
	status := c.Query("status")
	taskID := c.Query("task_id")

	query := `
		SELECT id, task_id, framework, control_id, name, evidence_type,
		       COALESCE(content,''), COALESCE(file_path,''), collected_at,
		       COALESCE(collected_by,''), status, reviewer_id, reviewed_at, expires_at
		FROM compliance_evidence_items
		WHERE 1=1`
	args := []interface{}{}
	argIdx := 1

	if framework != "" {
		query += fmt.Sprintf(" AND framework=$%d", argIdx)
		args = append(args, framework)
		argIdx++
	}
	if controlID != "" {
		query += fmt.Sprintf(" AND control_id=$%d", argIdx)
		args = append(args, controlID)
		argIdx++
	}
	if status != "" {
		query += fmt.Sprintf(" AND status=$%d", argIdx)
		args = append(args, status)
		argIdx++
	}
	if taskID != "" {
		query += fmt.Sprintf(" AND task_id=$%d", argIdx)
		args = append(args, taskID)
		argIdx++
	}
	_ = argIdx
	query += " ORDER BY collected_at DESC LIMIT 500"

	rows, err := h.pool.Query(c.Request.Context(), query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	defer rows.Close()

	type EvidenceItem struct {
		ID           string     `json:"id"`
		TaskID       string     `json:"task_id"`
		Framework    string     `json:"framework"`
		ControlID    string     `json:"control_id"`
		Name         string     `json:"name"`
		EvidenceType string     `json:"evidence_type"`
		Content      string     `json:"content"`
		FilePath     string     `json:"file_path"`
		CollectedAt  time.Time  `json:"collected_at"`
		CollectedBy  string     `json:"collected_by"`
		Status       string     `json:"status"`
		ReviewerID   *string    `json:"reviewer_id"`
		ReviewedAt   *time.Time `json:"reviewed_at"`
		ExpiresAt    *time.Time `json:"expires_at"`
	}

	var items []EvidenceItem
	for rows.Next() {
		var item EvidenceItem
		if err := rows.Scan(&item.ID, &item.TaskID, &item.Framework, &item.ControlID,
			&item.Name, &item.EvidenceType, &item.Content, &item.FilePath,
			&item.CollectedAt, &item.CollectedBy, &item.Status,
			&item.ReviewerID, &item.ReviewedAt, &item.ExpiresAt); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
			return
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		slog.Error("rows.Err: 結果の読み出しが途中で失敗しました", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if items == nil {
		items = []EvidenceItem{}
	}
	c.JSON(http.StatusOK, gin.H{"evidence": items})
}

// ReviewEvidence PATCH /evidence/:id/review — body: {status, notes}
func (h *ComplianceEvidenceHandler) ReviewEvidence(c *gin.Context) {
	id := c.Param("id")
	var body struct {
		Status string `json:"status" binding:"required"`
		Notes  string `json:"notes"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID, _ := c.Get("user_id")
	userIDStr, _ := userID.(string)

	var tag interface{ RowsAffected() int64 }
	var err error

	if userIDStr != "" {
		tag, err = h.pool.Exec(c.Request.Context(), `
			UPDATE compliance_evidence_items
			SET status=$1, reviewer_id=$2::uuid, reviewed_at=NOW()
			WHERE id=$3
		`, body.Status, userIDStr, id)
	} else {
		tag, err = h.pool.Exec(c.Request.Context(), `
			UPDATE compliance_evidence_items
			SET status=$1, reviewed_at=NOW()
			WHERE id=$2
		`, body.Status, id)
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": body.Status})
}

// GetStats GET /stats — evidence counts by framework, by status, expiring within 30 days
func (h *ComplianceEvidenceHandler) GetStats(c *gin.Context) {
	ctx := c.Request.Context()

	// Evidence counts by framework
	frameworkRows, err := h.pool.Query(ctx, `
		SELECT framework, COUNT(*) FROM compliance_evidence_items GROUP BY framework
	`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	defer frameworkRows.Close()
	byFramework := map[string]int{}
	for frameworkRows.Next() {
		var fw string
		var count int
		if err := frameworkRows.Scan(&fw, &count); err == nil {
			byFramework[fw] = count
		}
	}
	if err := frameworkRows.Err(); err != nil {
		slog.Error("rows.Err: 結果の読み出しが途中で失敗しました", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}

	// Evidence counts by status
	statusRows, err := h.pool.Query(ctx, `
		SELECT status, COUNT(*) FROM compliance_evidence_items GROUP BY status
	`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	defer statusRows.Close()
	byStatus := map[string]int{}
	for statusRows.Next() {
		var s string
		var count int
		if err := statusRows.Scan(&s, &count); err == nil {
			byStatus[s] = count
		}
	}
	if err := statusRows.Err(); err != nil {
		slog.Error("rows.Err: 結果の読み出しが途中で失敗しました", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}

	// Expiring within 30 days
	var expiringCount int
	if !ReadOK(c, h.pool.QueryRow(ctx, `
			SELECT COUNT(*) FROM compliance_evidence_items
			WHERE expires_at IS NOT NULL AND expires_at <= NOW() + INTERVAL '30 days' AND expires_at > NOW()
		`).Scan(&expiringCount)) {
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"by_framework":        byFramework,
		"by_status":           byStatus,
		"expiring_within_30d": expiringCount,
	})
}
