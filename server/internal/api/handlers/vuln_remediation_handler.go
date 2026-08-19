package handlers

import (
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// VulnRemediationHandler manages vulnerability remediation tracking endpoints.
type VulnRemediationHandler struct {
	pool *pgxpool.Pool
}

// NewVulnRemediationHandler creates a new VulnRemediationHandler.
func NewVulnRemediationHandler(pool *pgxpool.Pool) *VulnRemediationHandler {
	return &VulnRemediationHandler{pool: pool}
}

func (h *VulnRemediationHandler) tableExists(c *gin.Context) bool {
	return tableIsThere(c.Request.Context(), h.pool, "vuln_remediations")
}

// List — GET /vuln-remediations
func (h *VulnRemediationHandler) List(c *gin.Context) {
	if !h.tableExists(c) {
		c.JSON(http.StatusOK, gin.H{"remediations": []interface{}{}, "total": 0})
		return
	}
	ctx := c.Request.Context()

	limit, _ := strconv.Atoi(c.DefaultQuery("per_page", "50"))
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	page, limit, offset := clampPageParams(page, limit, 50, 200)

	query := `SELECT id, vuln_id, agent_id, cve_id, title, severity, status,
	                 assignee_id, due_date, resolution_notes, patch_version,
	                 verified_at, verified_by, created_at, updated_at
	          FROM vuln_remediations WHERE 1=1`
	args := []interface{}{}
	argIdx := 1

	if v := c.Query("status"); v != "" {
		query += fmt.Sprintf(" AND status=$%d", argIdx)
		args = append(args, v)
		argIdx++
	}
	if v := c.Query("severity"); v != "" {
		query += fmt.Sprintf(" AND severity=$%d", argIdx)
		args = append(args, v)
		argIdx++
	}
	if v := c.Query("assignee_id"); v != "" {
		query += fmt.Sprintf(" AND assignee_id=$%d", argIdx)
		args = append(args, v)
		argIdx++
	}
	if v := c.Query("agent_id"); v != "" {
		query += fmt.Sprintf(" AND agent_id=$%d", argIdx)
		args = append(args, v)
		argIdx++
	}
	if c.Query("overdue") == "true" {
		query += " AND due_date < CURRENT_DATE AND status NOT IN ('verified','closed')"
	}

	countQuery := "SELECT COUNT(*) FROM (" + query + ") sub"
	var total int
	if !ReadOK(c, h.pool.QueryRow(ctx, countQuery, args...).Scan(&total)) {
		return
	}

	query += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	args = append(args, limit, offset)

	rows, err := h.pool.Query(ctx, query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "リメディエーション一覧の取得に失敗しました"})
		return
	}
	defer rows.Close()

	type remediation struct {
		ID              string  `json:"id"`
		VulnID          string  `json:"vuln_id"`
		AgentID         string  `json:"agent_id"`
		CVEID           string  `json:"cve_id"`
		Title           string  `json:"title"`
		Severity        string  `json:"severity"`
		Status          string  `json:"status"`
		AssigneeID      *string `json:"assignee_id"`
		DueDate         *string `json:"due_date"`
		ResolutionNotes string  `json:"resolution_notes"`
		PatchVersion    string  `json:"patch_version"`
		VerifiedAt      *string `json:"verified_at"`
		VerifiedBy      *string `json:"verified_by"`
		CreatedAt       string  `json:"created_at"`
		UpdatedAt       string  `json:"updated_at"`
	}

	var result []remediation
	for rows.Next() {
		var r remediation
		var createdAt, updatedAt time.Time
		var verifiedAt *time.Time
		var dueDate *string
		if err := rows.Scan(&r.ID, &r.VulnID, &r.AgentID, &r.CVEID, &r.Title,
			&r.Severity, &r.Status, &r.AssigneeID, &dueDate, &r.ResolutionNotes,
			&r.PatchVersion, &verifiedAt, &r.VerifiedBy, &createdAt, &updatedAt); err != nil {
			continue
		}
		r.CreatedAt = createdAt.Format(time.RFC3339)
		r.UpdatedAt = updatedAt.Format(time.RFC3339)
		r.DueDate = dueDate
		if verifiedAt != nil {
			t := verifiedAt.Format(time.RFC3339)
			r.VerifiedAt = &t
		}
		result = append(result, r)
	}
	if err := rows.Err(); err != nil {
		slog.Error("rows.Err: 結果の読み出しが途中で失敗しました", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "リメディエーション一覧の取得に失敗しました"})
		return
	}
	if result == nil {
		result = []remediation{}
	}
	c.JSON(http.StatusOK, gin.H{"remediations": result, "total": total, "page": page})
}

// Get — GET /vuln-remediations/:id
func (h *VulnRemediationHandler) Get(c *gin.Context) {
	if !h.tableExists(c) {
		c.JSON(http.StatusNotFound, gin.H{"error": "リメディエーションが見つかりません"})
		return
	}
	ctx := c.Request.Context()
	id := c.Param("id")

	row := h.pool.QueryRow(ctx,
		`SELECT id, vuln_id, agent_id, cve_id, title, severity, status,
		        assignee_id, due_date, resolution_notes, patch_version,
		        verified_at, verified_by, created_at, updated_at
		 FROM vuln_remediations WHERE id=$1`, id)

	var (
		rID, vulnID, agentID, cveID, title, severity, status, resNotes, patchVersion string
		assigneeID, verifiedBy                                                       *string
		dueDate                                                                      *string
		verifiedAt                                                                   *time.Time
		createdAt, updatedAt                                                         time.Time
	)
	if err := row.Scan(&rID, &vulnID, &agentID, &cveID, &title, &severity, &status,
		&assigneeID, &dueDate, &resNotes, &patchVersion, &verifiedAt, &verifiedBy,
		&createdAt, &updatedAt); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "リメディエーションが見つかりません"})
		return
	}

	resp := gin.H{
		"id":               rID,
		"vuln_id":          vulnID,
		"agent_id":         agentID,
		"cve_id":           cveID,
		"title":            title,
		"severity":         severity,
		"status":           status,
		"assignee_id":      assigneeID,
		"due_date":         dueDate,
		"resolution_notes": resNotes,
		"patch_version":    patchVersion,
		"verified_by":      verifiedBy,
		"created_at":       createdAt.Format(time.RFC3339),
		"updated_at":       updatedAt.Format(time.RFC3339),
		"verified_at":      nil,
	}
	if verifiedAt != nil {
		resp["verified_at"] = verifiedAt.Format(time.RFC3339)
	}
	c.JSON(http.StatusOK, resp)
}

// Create — POST /vuln-remediations
func (h *VulnRemediationHandler) Create(c *gin.Context) {
	if !h.tableExists(c) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "テーブルが存在しません"})
		return
	}
	ctx := c.Request.Context()

	var body struct {
		VulnID     string  `json:"vuln_id" binding:"required"`
		AgentID    string  `json:"agent_id" binding:"required"`
		CVEID      string  `json:"cve_id"`
		Title      string  `json:"title" binding:"required"`
		Severity   string  `json:"severity"`
		AssigneeID *string `json:"assignee_id"`
		DueDate    *string `json:"due_date"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "リクエストボディが無効です"})
		return
	}
	if body.VulnID == "" || body.AgentID == "" || body.Title == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "vuln_id, agent_id, titleは必須です"})
		return
	}
	if body.Severity == "" {
		body.Severity = "medium"
	}

	var id string
	err := h.pool.QueryRow(ctx,
		`INSERT INTO vuln_remediations (vuln_id, agent_id, cve_id, title, severity, assignee_id, due_date)
		 VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
		body.VulnID, body.AgentID, body.CVEID, body.Title, body.Severity,
		body.AssigneeID, body.DueDate).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "リメディエーションの作成に失敗しました"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id, "message": "リメディエーションを作成しました"})
}

// Update — PUT /vuln-remediations/:id
func (h *VulnRemediationHandler) Update(c *gin.Context) {
	if !h.tableExists(c) {
		c.JSON(http.StatusNotFound, gin.H{"error": "リメディエーションが見つかりません"})
		return
	}
	ctx := c.Request.Context()
	id := c.Param("id")

	var body struct {
		Status          *string `json:"status"`
		AssigneeID      *string `json:"assignee_id"`
		ResolutionNotes *string `json:"resolution_notes"`
		DueDate         *string `json:"due_date"`
		PatchVersion    *string `json:"patch_version"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "リクエストボディが無効です"})
		return
	}

	query := "UPDATE vuln_remediations SET updated_at=NOW()"
	args := []interface{}{}
	argIdx := 1

	if body.Status != nil {
		query += fmt.Sprintf(", status=$%d", argIdx)
		args = append(args, *body.Status)
		argIdx++
	}
	if body.AssigneeID != nil {
		query += fmt.Sprintf(", assignee_id=$%d", argIdx)
		args = append(args, *body.AssigneeID)
		argIdx++
	}
	if body.ResolutionNotes != nil {
		query += fmt.Sprintf(", resolution_notes=$%d", argIdx)
		args = append(args, *body.ResolutionNotes)
		argIdx++
	}
	if body.DueDate != nil {
		query += fmt.Sprintf(", due_date=$%d", argIdx)
		args = append(args, *body.DueDate)
		argIdx++
	}
	if body.PatchVersion != nil {
		query += fmt.Sprintf(", patch_version=$%d", argIdx)
		args = append(args, *body.PatchVersion)
		argIdx++
	}

	query += fmt.Sprintf(" WHERE id=$%d", argIdx)
	args = append(args, id)

	_, err := h.pool.Exec(ctx, query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "更新に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "更新しました"})
}

// Verify — POST /vuln-remediations/:id/verify
func (h *VulnRemediationHandler) Verify(c *gin.Context) {
	if !h.tableExists(c) {
		c.JSON(http.StatusNotFound, gin.H{"error": "リメディエーションが見つかりません"})
		return
	}
	ctx := c.Request.Context()
	id := c.Param("id")

	userID, _ := c.Get("user_id")
	userIDStr, _ := userID.(string)

	_, err := h.pool.Exec(ctx,
		`UPDATE vuln_remediations SET status='verified', verified_at=NOW(), verified_by=$1, updated_at=NOW()
		 WHERE id=$2`, userIDStr, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "検証に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "リメディエーションを検証済みにしました"})
}

// BulkAssign — POST /vuln-remediations/bulk-assign
func (h *VulnRemediationHandler) BulkAssign(c *gin.Context) {
	if !h.tableExists(c) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "テーブルが存在しません"})
		return
	}
	ctx := c.Request.Context()

	var body struct {
		IDs        []string `json:"ids"`
		AssigneeID string   `json:"assignee_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "リクエストボディが無効です"})
		return
	}
	if len(body.IDs) == 0 || body.AssigneeID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ids と assignee_id は必須です"})
		return
	}

	// Build parameterized IN clause
	query := "UPDATE vuln_remediations SET assignee_id=$1, updated_at=NOW() WHERE id IN ("
	args := []interface{}{body.AssigneeID}
	for i, id := range body.IDs {
		if i > 0 {
			query += ","
		}
		query += fmt.Sprintf("$%d", i+2)
		args = append(args, id)
	}
	query += ")"

	ct, err := h.pool.Exec(ctx, query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "一括割り当てに失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"updated": ct.RowsAffected(), "message": "一括割り当てが完了しました"})
}

// GetStats — GET /vuln-remediations/stats
func (h *VulnRemediationHandler) GetStats(c *gin.Context) {
	if !h.tableExists(c) {
		c.JSON(http.StatusOK, gin.H{
			"open":                0,
			"in_progress":         0,
			"verified":            0,
			"overdue":             0,
			"by_severity":         gin.H{},
			"avg_days_to_resolve": 0,
		})
		return
	}
	ctx := c.Request.Context()

	var open, inProgress, verified, overdue int
	if !ReadOK(c, h.pool.QueryRow(ctx,
		`SELECT
			   COUNT(*) FILTER (WHERE status='open'),
			   COUNT(*) FILTER (WHERE status='in_progress'),
			   COUNT(*) FILTER (WHERE status='verified'),
			   COUNT(*) FILTER (WHERE due_date < CURRENT_DATE AND status NOT IN ('verified','closed'))
			 FROM vuln_remediations`).Scan(&open, &inProgress, &verified, &overdue)) {
		return
	}

	rows, err := h.pool.Query(ctx,
		`SELECT severity, COUNT(*) FROM vuln_remediations GROUP BY severity`)
	if !ReadOK(c, err) {
		return
	}
	bySeverity := gin.H{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var sev string
			var cnt int
			if rows.Scan(&sev, &cnt) == nil {
				bySeverity[sev] = cnt
			}
		}
		if err := rows.Err(); err != nil {
			slog.Warn("row iteration error", "error", err)
		}
	}

	var avgDays float64
	if !ReadOK(c, h.pool.QueryRow(ctx,
		`SELECT COALESCE(AVG(EXTRACT(EPOCH FROM (verified_at - created_at))/86400), 0)
			 FROM vuln_remediations WHERE status='verified' AND verified_at IS NOT NULL`).Scan(&avgDays)) {
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"open":                open,
		"in_progress":         inProgress,
		"verified":            verified,
		"overdue":             overdue,
		"by_severity":         bySeverity,
		"avg_days_to_resolve": avgDays,
	})
}
