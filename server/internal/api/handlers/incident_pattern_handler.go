package handlers

import (
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// IncidentPatternHandler manages incident pattern recognition.
type IncidentPatternHandler struct {
	pool *pgxpool.Pool
}

// NewIncidentPatternHandler creates a new IncidentPatternHandler.
func NewIncidentPatternHandler(pool *pgxpool.Pool) *IncidentPatternHandler {
	return &IncidentPatternHandler{pool: pool}
}

func (h *IncidentPatternHandler) checkPatternsTable(c *gin.Context) bool {
	return tableIsThere(c.Request.Context(), h.pool, "incident_patterns")
}

func (h *IncidentPatternHandler) checkMatchesTable(c *gin.Context) bool {
	return tableIsThere(c.Request.Context(), h.pool, "pattern_matches")
}

// ListPatterns returns all incident patterns.
// GET /api/v1/admin/incident-patterns/patterns
func (h *IncidentPatternHandler) ListPatterns(c *gin.Context) {
	if !h.checkPatternsTable(c) {
		c.JSON(http.StatusOK, gin.H{"patterns": []interface{}{}, "total": 0})
		return
	}
	ctx := c.Request.Context()
	rows, err := h.pool.Query(ctx,
		`SELECT id, name, description, pattern_type, conditions, severity,
		        confidence_threshold, match_count, is_active, created_at, updated_at
		 FROM incident_patterns ORDER BY created_at DESC`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list patterns"})
		return
	}
	defer rows.Close()

	type pattern struct {
		ID                  string      `json:"id"`
		Name                string      `json:"name"`
		Description         *string     `json:"description"`
		PatternType         string      `json:"pattern_type"`
		Conditions          interface{} `json:"conditions"`
		Severity            string      `json:"severity"`
		ConfidenceThreshold float64     `json:"confidence_threshold"`
		MatchCount          int         `json:"match_count"`
		IsActive            bool        `json:"is_active"`
		CreatedAt           string      `json:"created_at"`
		UpdatedAt           string      `json:"updated_at"`
	}

	var result []pattern
	for rows.Next() {
		var p pattern
		var conditionsRaw []byte
		var createdAt, updatedAt time.Time
		if err := rows.Scan(
			&p.ID, &p.Name, &p.Description, &p.PatternType, &conditionsRaw,
			&p.Severity, &p.ConfidenceThreshold, &p.MatchCount, &p.IsActive,
			&createdAt, &updatedAt,
		); err != nil {
			continue
		}
		p.CreatedAt = createdAt.Format(time.RFC3339)
		p.UpdatedAt = updatedAt.Format(time.RFC3339)
		p.Conditions = jsonRawOrEmpty(conditionsRaw)
		result = append(result, p)
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if result == nil {
		result = []pattern{}
	}
	c.JSON(http.StatusOK, gin.H{"patterns": result, "total": len(result)})
}

// CreatePattern creates a new incident pattern.
// POST /api/v1/admin/incident-patterns/patterns
func (h *IncidentPatternHandler) CreatePattern(c *gin.Context) {
	if !h.checkPatternsTable(c) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "incident_patterns table not available"})
		return
	}
	var body struct {
		Name                string   `json:"name" binding:"required"`
		Description         *string  `json:"description"`
		PatternType         string   `json:"pattern_type"`
		Conditions          *string  `json:"conditions"`
		Severity            string   `json:"severity"`
		ConfidenceThreshold *float64 `json:"confidence_threshold"`
		IsActive            *bool    `json:"is_active"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	if body.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}
	if body.PatternType == "" {
		body.PatternType = "sequence"
	}
	if body.Severity == "" {
		body.Severity = "medium"
	}
	threshold := 0.7
	if body.ConfidenceThreshold != nil {
		threshold = *body.ConfidenceThreshold
	}
	isActive := true
	if body.IsActive != nil {
		isActive = *body.IsActive
	}
	conditions := "[]"
	if body.Conditions != nil && *body.Conditions != "" {
		conditions = *body.Conditions
	}

	ctx := c.Request.Context()
	var id string
	err := h.pool.QueryRow(ctx,
		`INSERT INTO incident_patterns (name, description, pattern_type, conditions, severity, confidence_threshold, is_active)
		 VALUES ($1,$2,$3,$4::jsonb,$5,$6,$7) RETURNING id`,
		body.Name, body.Description, body.PatternType, conditions,
		body.Severity, threshold, isActive,
	).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create pattern"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id, "message": "Pattern created"})
}

// UpdatePattern updates an existing incident pattern.
// PUT /api/v1/admin/incident-patterns/patterns/:id
func (h *IncidentPatternHandler) UpdatePattern(c *gin.Context) {
	if !h.checkPatternsTable(c) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Not found"})
		return
	}
	id := c.Param("id")
	var body struct {
		Name                string   `json:"name" binding:"required"`
		Description         *string  `json:"description"`
		PatternType         string   `json:"pattern_type"`
		Conditions          *string  `json:"conditions"`
		Severity            string   `json:"severity"`
		ConfidenceThreshold *float64 `json:"confidence_threshold"`
		IsActive            *bool    `json:"is_active"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	conditions := "[]"
	if body.Conditions != nil && *body.Conditions != "" {
		conditions = *body.Conditions
	}
	ctx := c.Request.Context()
	_, err := h.pool.Exec(ctx,
		`UPDATE incident_patterns SET name=$1, description=$2, pattern_type=$3, conditions=$4::jsonb,
		        severity=$5, confidence_threshold=$6, is_active=$7, updated_at=NOW()
		 WHERE id=$8`,
		body.Name, body.Description, body.PatternType, conditions,
		body.Severity, body.ConfidenceThreshold, body.IsActive, id,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update pattern"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Pattern updated"})
}

// DeletePattern deletes an incident pattern.
// DELETE /api/v1/admin/incident-patterns/patterns/:id
func (h *IncidentPatternHandler) DeletePattern(c *gin.Context) {
	if !h.checkPatternsTable(c) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Not found"})
		return
	}
	id := c.Param("id")
	ctx := c.Request.Context()
	_, err := h.pool.Exec(ctx, `DELETE FROM incident_patterns WHERE id=$1`, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete pattern"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Pattern deleted"})
}

// TogglePattern flips the is_active state of a pattern.
// POST /api/v1/admin/incident-patterns/patterns/:id/toggle
func (h *IncidentPatternHandler) TogglePattern(c *gin.Context) {
	if !h.checkPatternsTable(c) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Not found"})
		return
	}
	id := c.Param("id")
	ctx := c.Request.Context()
	var isActive bool
	err := h.pool.QueryRow(ctx,
		`UPDATE incident_patterns SET is_active = NOT is_active, updated_at=NOW()
		 WHERE id=$1 RETURNING is_active`, id,
	).Scan(&isActive)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to toggle pattern"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"is_active": isActive})
}

// RunAnalysis POST /api/v1/admin/incident-patterns/analyze
//
// パターンマッチングエンジンは未実装。以前は rand.Float64() による乱数の信頼度で
// 偽のパターンマッチを pattern_matches に挿入していたが、これは存在しない脅威を
// 検出済みと偽装するもので、セキュリティ製品として重大な信頼性問題があった。
// 偽マッチ生成を完全に廃止し、相関エンジン実装までは準備中(503)を返す。
// 実装時はここに実インシデント相関ロジック（パターン条件 vs インシデント属性の
// 突合）を配線し、本物のマッチのみを挿入すること。
func (h *IncidentPatternHandler) RunAnalysis(c *gin.Context) {
	if !h.checkPatternsTable(c) || !h.checkMatchesTable(c) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Required tables not available"})
		return
	}
	c.JSON(http.StatusServiceUnavailable, gin.H{
		"error": "パターン分析エンジンは準備中です。インシデント相関ロジックが未実装のため、分析は実行できません。",
	})
}

// ListMatches returns pattern matches with optional filters.
// GET /api/v1/admin/incident-patterns/matches
func (h *IncidentPatternHandler) ListMatches(c *gin.Context) {
	if !h.checkMatchesTable(c) {
		c.JSON(http.StatusOK, gin.H{"matches": []interface{}{}, "total": 0})
		return
	}
	patternID := c.Query("pattern_id")
	status := c.Query("status")

	ctx := c.Request.Context()
	args := []interface{}{}
	where := "WHERE 1=1"
	idx := 1
	if patternID != "" {
		where += " AND pattern_id=$" + strconv.Itoa(idx)
		args = append(args, patternID)
		idx++
	}
	if status != "" {
		where += " AND status=$" + strconv.Itoa(idx)
		args = append(args, status)
		idx++
	}

	query := `SELECT id, pattern_id, incident_ids, confidence, summary, details, status, created_at
	          FROM pattern_matches ` + where + ` ORDER BY created_at DESC LIMIT 100`
	rows, err := h.pool.Query(ctx, query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list matches"})
		return
	}
	defer rows.Close()

	type match struct {
		ID          string      `json:"id"`
		PatternID   string      `json:"pattern_id"`
		IncidentIDs interface{} `json:"incident_ids"`
		Confidence  float64     `json:"confidence"`
		Summary     *string     `json:"summary"`
		Details     interface{} `json:"details"`
		Status      string      `json:"status"`
		CreatedAt   string      `json:"created_at"`
	}

	var result []match
	for rows.Next() {
		var m match
		var createdAt time.Time
		var incidentIDsRaw, detailsRaw []byte
		if err := rows.Scan(
			&m.ID, &m.PatternID, &incidentIDsRaw, &m.Confidence,
			&m.Summary, &detailsRaw, &m.Status, &createdAt,
		); err != nil {
			continue
		}
		m.CreatedAt = createdAt.Format(time.RFC3339)
		m.IncidentIDs = jsonRawOrEmpty(incidentIDsRaw)
		m.Details = jsonRawOrEmpty(detailsRaw)
		result = append(result, m)
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if result == nil {
		result = []match{}
	}
	c.JSON(http.StatusOK, gin.H{"matches": result, "total": len(result)})
}

// UpdateMatchStatus updates the status of a pattern match.
// PATCH /api/v1/admin/incident-patterns/matches/:id/status
func (h *IncidentPatternHandler) UpdateMatchStatus(c *gin.Context) {
	if !h.checkMatchesTable(c) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Not found"})
		return
	}
	id := c.Param("id")
	var body struct {
		Status string `json:"status" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Status == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "status is required"})
		return
	}
	ctx := c.Request.Context()
	_, err := h.pool.Exec(ctx,
		`UPDATE pattern_matches SET status=$1 WHERE id=$2`, body.Status, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update match status"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Match status updated"})
}

// GetStats returns pattern match statistics.
// GET /api/v1/admin/incident-patterns/stats
func (h *IncidentPatternHandler) GetStats(c *gin.Context) {
	if !h.checkPatternsTable(c) {
		c.JSON(http.StatusOK, gin.H{
			"match_counts_by_type": []interface{}{},
			"top_patterns":         []interface{}{},
			"recent_match_trend":   []interface{}{},
		})
		return
	}
	ctx := c.Request.Context()

	// Match counts by pattern_type
	type typeCount struct {
		PatternType string `json:"pattern_type"`
		Count       int    `json:"count"`
	}
	var byType []typeCount
	if h.checkMatchesTable(c) {
		rows, err := h.pool.Query(ctx,
			`SELECT ip.pattern_type, COUNT(pm.id)
			 FROM incident_patterns ip
			 LEFT JOIN pattern_matches pm ON ip.id = pm.pattern_id
			 GROUP BY ip.pattern_type ORDER BY COUNT(pm.id) DESC`)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var t typeCount
				if err := rows.Scan(&t.PatternType, &t.Count); err == nil {
					byType = append(byType, t)
				}
			}
			if err := rows.Err(); err != nil {
				slog.Warn("incident byType iteration failed", "error", err)
			}
		}
	}
	if byType == nil {
		byType = []typeCount{}
	}

	// Top patterns by match count
	type topPattern struct {
		ID         string `json:"id"`
		Name       string `json:"name"`
		MatchCount int    `json:"match_count"`
	}
	var topPatterns []topPattern
	rows, err := h.pool.Query(ctx,
		`SELECT id, name, match_count FROM incident_patterns ORDER BY match_count DESC LIMIT 10`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var tp topPattern
			if err := rows.Scan(&tp.ID, &tp.Name, &tp.MatchCount); err == nil {
				topPatterns = append(topPatterns, tp)
			}
		}
		if err := rows.Err(); err != nil {
			slog.Warn("incident topPatterns iteration failed", "error", err)
		}
	}
	if topPatterns == nil {
		topPatterns = []topPattern{}
	}

	// Recent match trend (last 7 days)
	type dayCount struct {
		Date  string `json:"date"`
		Count int    `json:"count"`
	}
	var recentTrend []dayCount
	if h.checkMatchesTable(c) {
		rows, err := h.pool.Query(ctx,
			`SELECT DATE(created_at)::text, COUNT(*) FROM pattern_matches
			 WHERE created_at >= NOW() - INTERVAL '7 days'
			 GROUP BY DATE(created_at) ORDER BY DATE(created_at)`)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var d dayCount
				if err := rows.Scan(&d.Date, &d.Count); err == nil {
					recentTrend = append(recentTrend, d)
				}
			}
			if err := rows.Err(); err != nil {
				slog.Warn("incident trend iteration failed", "error", err)
			}
		}
	}
	if recentTrend == nil {
		recentTrend = []dayCount{}
	}

	c.JSON(http.StatusOK, gin.H{
		"match_counts_by_type": byType,
		"top_patterns":         topPatterns,
		"recent_match_trend":   recentTrend,
	})
}
