package handlers

import (
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// DLPHandler manages Data Loss Prevention rules and violations.
type DLPHandler struct {
	pool *pgxpool.Pool
}

// NewDLPHandler creates a new DLPHandler.
func NewDLPHandler(pool *pgxpool.Pool) *DLPHandler {
	return &DLPHandler{pool: pool}
}

type dlpRule struct {
	ID           string  `json:"id"`
	Name         string  `json:"name"`
	Description  string  `json:"description"`
	Pattern      string  `json:"pattern"`
	PatternType  string  `json:"pattern_type"`
	DataCategory string  `json:"data_category"`
	Action       string  `json:"action"`
	Severity     int     `json:"severity"`
	Enabled      bool    `json:"enabled"`
	MatchCount   int     `json:"match_count"`
	CreatedBy    *string `json:"created_by,omitempty"`
	CreatedAt    string  `json:"created_at"`
	UpdatedAt    string  `json:"updated_at"`
}

const dlpRuleCols = `id, name, description, pattern, pattern_type, data_category,
	action, severity, enabled, match_count, created_by, created_at, updated_at`

func scanDLPRule(row interface{ Scan(...any) error }) (*dlpRule, error) {
	var r dlpRule
	var createdAt, updatedAt time.Time
	err := row.Scan(
		&r.ID, &r.Name, &r.Description, &r.Pattern, &r.PatternType,
		&r.DataCategory, &r.Action, &r.Severity, &r.Enabled, &r.MatchCount,
		&r.CreatedBy, &createdAt, &updatedAt,
	)
	if err != nil {
		return nil, err
	}
	r.CreatedAt = createdAt.Format(time.RFC3339)
	r.UpdatedAt = updatedAt.Format(time.RFC3339)
	return &r, nil
}

// ListRules returns all DLP rules.
// GET /api/v1/admin/dlp/rules
func (h *DLPHandler) ListRules(c *gin.Context) {
	ctx := c.Request.Context()

	exists := tableIsThere(ctx, h.pool, "dlp_rules")
	if !exists {
		c.JSON(http.StatusOK, gin.H{"data": []interface{}{}, "total": 0})
		return
	}

	rows, err := h.pool.Query(ctx,
		`SELECT `+dlpRuleCols+` FROM dlp_rules ORDER BY created_at DESC`,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list DLP rules"})
		return
	}
	defer rows.Close()

	rules := []*dlpRule{}
	for rows.Next() {
		r, err := scanDLPRule(rows)
		if err == nil {
			rules = append(rules, r)
		}
	}
	if err := rows.Err(); err != nil {
		slog.Error("rows.Err: 結果の読み出しが途中で失敗しました", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list DLP rules"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": rules, "total": len(rules)})
}

// CreateRule creates a new DLP rule.
// POST /api/v1/admin/dlp/rules
func (h *DLPHandler) CreateRule(c *gin.Context) {
	var req struct {
		Name         string `json:"name"          binding:"required"`
		Description  string `json:"description"`
		Pattern      string `json:"pattern"       binding:"required"`
		PatternType  string `json:"pattern_type"`
		DataCategory string `json:"data_category"`
		Action       string `json:"action"`
		Severity     int    `json:"severity"`
		Enabled      *bool  `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}
	if strings.TrimSpace(req.Pattern) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "pattern is required"})
		return
	}
	if req.PatternType == "" {
		req.PatternType = "regex"
	}
	if req.DataCategory == "" {
		req.DataCategory = "pii"
	}
	if req.Action == "" {
		req.Action = "alert"
	}
	if req.Severity == 0 {
		req.Severity = 7
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	userID, _ := c.Get("user_id")
	uid, _ := userID.(string)
	var createdBy *string
	if uid != "" {
		createdBy = &uid
	}

	row := h.pool.QueryRow(c.Request.Context(),
		`INSERT INTO dlp_rules (name, description, pattern, pattern_type, data_category, action, severity, enabled, created_by)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		 RETURNING `+dlpRuleCols,
		req.Name, req.Description, req.Pattern, req.PatternType,
		req.DataCategory, req.Action, req.Severity, enabled, createdBy,
	)
	r, err := scanDLPRule(row)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create DLP rule"})
		return
	}
	c.JSON(http.StatusCreated, r)
}

// UpdateRule updates an existing DLP rule.
// PUT /api/v1/admin/dlp/rules/:id
func (h *DLPHandler) UpdateRule(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Name         string `json:"name"`
		Description  string `json:"description"`
		Pattern      string `json:"pattern"`
		PatternType  string `json:"pattern_type"`
		DataCategory string `json:"data_category"`
		Action       string `json:"action"`
		Severity     int    `json:"severity"`
		Enabled      *bool  `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if strings.TrimSpace(req.Pattern) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "pattern is required"})
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	row := h.pool.QueryRow(c.Request.Context(),
		`UPDATE dlp_rules SET
		   name          = $2,
		   description   = $3,
		   pattern       = $4,
		   pattern_type  = $5,
		   data_category = $6,
		   action        = $7,
		   severity      = $8,
		   enabled       = $9,
		   updated_at    = NOW()
		 WHERE id = $1
		 RETURNING `+dlpRuleCols,
		id, req.Name, req.Description, req.Pattern, req.PatternType,
		req.DataCategory, req.Action, req.Severity, enabled,
	)
	r, err := scanDLPRule(row)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			c.JSON(http.StatusNotFound, gin.H{"error": "DLP rule not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update DLP rule"})
		return
	}
	c.JSON(http.StatusOK, r)
}

// DeleteRule removes a DLP rule.
// DELETE /api/v1/admin/dlp/rules/:id
func (h *DLPHandler) DeleteRule(c *gin.Context) {
	id := c.Param("id")
	tag, err := h.pool.Exec(c.Request.Context(),
		`DELETE FROM dlp_rules WHERE id = $1`, id,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete DLP rule"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "DLP rule not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "DLP rule deleted"})
}

// ToggleRule flips the enabled state of a DLP rule.
// POST /api/v1/admin/dlp/rules/:id/toggle
func (h *DLPHandler) ToggleRule(c *gin.Context) {
	id := c.Param("id")
	row := h.pool.QueryRow(c.Request.Context(),
		`UPDATE dlp_rules SET enabled = NOT enabled, updated_at = NOW()
		 WHERE id = $1
		 RETURNING `+dlpRuleCols,
		id,
	)
	r, err := scanDLPRule(row)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			c.JSON(http.StatusNotFound, gin.H{"error": "DLP rule not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to toggle DLP rule"})
		return
	}
	c.JSON(http.StatusOK, r)
}

// ListViolations returns DLP violations with optional filters.
// GET /api/v1/admin/dlp/violations
func (h *DLPHandler) ListViolations(c *gin.Context) {
	ctx := c.Request.Context()

	exists := tableIsThere(ctx, h.pool, "dlp_violations")
	if !exists {
		c.JSON(http.StatusOK, gin.H{"data": []interface{}{}, "total": 0})
		return
	}

	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if limit <= 0 || limit > 500 {
		limit = 50
	}

	agentID := c.Query("agent_id")
	ruleID := c.Query("rule_id")
	from := c.Query("from")
	to := c.Query("to")

	query := `SELECT id, rule_id, agent_id, file_path, process_name, matched_pattern, action_taken, detected_at
		 FROM dlp_violations WHERE 1=1`
	args := []interface{}{}
	n := 1

	if agentID != "" {
		query += ` AND agent_id = $` + strconv.Itoa(n)
		args = append(args, agentID)
		n++
	}
	if ruleID != "" {
		query += ` AND rule_id = $` + strconv.Itoa(n)
		args = append(args, ruleID)
		n++
	}
	if from != "" {
		query += ` AND detected_at >= $` + strconv.Itoa(n)
		args = append(args, from)
		n++
	}
	if to != "" {
		query += ` AND detected_at <= $` + strconv.Itoa(n)
		args = append(args, to)
		n++
	}

	var total int
	countQ := `SELECT COUNT(*) FROM dlp_violations WHERE 1=1`
	if agentID != "" {
		countQ += ` AND agent_id = '` + strings.ReplaceAll(agentID, "'", "''") + `'`
	}
	if ruleID != "" {
		countQ += ` AND rule_id = '` + strings.ReplaceAll(ruleID, "'", "''") + `'`
	}
	if !ReadOK(c, h.pool.QueryRow(ctx, countQ).Scan(&total)) {
		return
	}

	query += ` ORDER BY detected_at DESC LIMIT $` + strconv.Itoa(n) + ` OFFSET $` + strconv.Itoa(n+1)
	args = append(args, limit, offset)

	rows, err := h.pool.Query(ctx, query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list violations"})
		return
	}
	defer rows.Close()

	type violation struct {
		ID             string  `json:"id"`
		RuleID         string  `json:"rule_id"`
		AgentID        string  `json:"agent_id"`
		FilePath       *string `json:"file_path"`
		ProcessName    *string `json:"process_name"`
		MatchedPattern string  `json:"matched_pattern"`
		ActionTaken    string  `json:"action_taken"`
		DetectedAt     string  `json:"detected_at"`
	}

	violations := []violation{}
	for rows.Next() {
		var v violation
		var detectedAt time.Time
		if err := rows.Scan(
			&v.ID, &v.RuleID, &v.AgentID, &v.FilePath, &v.ProcessName,
			&v.MatchedPattern, &v.ActionTaken, &detectedAt,
		); err == nil {
			v.DetectedAt = detectedAt.Format(time.RFC3339)
			violations = append(violations, v)
		}
	}
	if err := rows.Err(); err != nil {
		slog.Error("rows.Err: 結果の読み出しが途中で失敗しました", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list violations"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data":     violations,
		"total":    total,
		"limit":    limit,
		"offset":   offset,
		"has_more": offset+limit < total,
	})
}

// GetStats returns DLP statistics.
// GET /api/v1/admin/dlp/stats
func (h *DLPHandler) GetStats(c *gin.Context) {
	ctx := c.Request.Context()

	type catStat struct {
		Category string `json:"category"`
		Count    int    `json:"count"`
	}
	type actionStat struct {
		Action string `json:"action"`
		Count  int    `json:"count"`
	}

	var violationsToday, violationsWeek int
	if !ReadOK(c, h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM dlp_violations WHERE detected_at >= CURRENT_DATE`).Scan(&violationsToday)) {
		return
	}
	if !ReadOK(c, h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM dlp_violations WHERE detected_at >= CURRENT_DATE - INTERVAL '7 days'`).Scan(&violationsWeek)) {
		return
	}

	var byCategory []catStat
	rows, err := h.pool.Query(ctx,
		`SELECT r.data_category, COUNT(v.id) as cnt
		 FROM dlp_violations v
		 JOIN dlp_rules r ON r.id = v.rule_id
		 GROUP BY r.data_category ORDER BY cnt DESC`,
	)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var s catStat
			if rows.Scan(&s.Category, &s.Count) == nil {
				byCategory = append(byCategory, s)
			}
		}
		if err := rows.Err(); err != nil {
			slog.Warn("row iteration error", "error", err)
		}
	}

	var byAction []actionStat
	rows2, err := h.pool.Query(ctx,
		`SELECT action_taken, COUNT(*) as cnt FROM dlp_violations GROUP BY action_taken ORDER BY cnt DESC`,
	)
	if err == nil {
		defer rows2.Close()
		for rows2.Next() {
			var s actionStat
			if rows2.Scan(&s.Action, &s.Count) == nil {
				byAction = append(byAction, s)
			}
		}
		if err := rows2.Err(); err != nil {
			slog.Warn("row iteration error", "error", err)
		}
	}

	if byCategory == nil {
		byCategory = []catStat{}
	}
	if byAction == nil {
		byAction = []actionStat{}
	}

	c.JSON(http.StatusOK, gin.H{
		"violations_today": violationsToday,
		"violations_week":  violationsWeek,
		"by_category":      byCategory,
		"by_action":        byAction,
	})
}
