package handlers

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CloudSIEMHandler manages cloud-native SIEM log sources, detection rules, and queries.
type CloudSIEMHandler struct {
	pool *pgxpool.Pool
}

func NewCloudSIEMHandler(pool *pgxpool.Pool) *CloudSIEMHandler {
	return &CloudSIEMHandler{pool: pool}
}

// ListLogSources GET /sources
func (h *CloudSIEMHandler) ListLogSources(c *gin.Context) {
	rows, err := h.pool.Query(c.Request.Context(), `
		SELECT id, name, source_type, config, is_active, daily_volume_mb,
		       last_received, error_count, created_at, updated_at
		FROM siem_log_sources
		ORDER BY created_at DESC
		LIMIT 500
	`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	defer rows.Close()

	type LogSource struct {
		ID            string      `json:"id"`
		Name          string      `json:"name"`
		SourceType    string      `json:"source_type"`
		Config        interface{} `json:"config"`
		IsActive      bool        `json:"is_active"`
		DailyVolumeMB int64       `json:"daily_volume_mb"`
		LastReceived  *time.Time  `json:"last_received"`
		ErrorCount    int         `json:"error_count"`
		CreatedAt     time.Time   `json:"created_at"`
		UpdatedAt     time.Time   `json:"updated_at"`
	}

	var sources []LogSource
	for rows.Next() {
		var s LogSource
		if err := rows.Scan(&s.ID, &s.Name, &s.SourceType, &s.Config, &s.IsActive,
			&s.DailyVolumeMB, &s.LastReceived, &s.ErrorCount, &s.CreatedAt, &s.UpdatedAt); err != nil {
			slog.Warn("cloud_siem: log sources scan error", "error", err)
			continue
		}
		sources = append(sources, s)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("cloud_siem: log sources rows error", "error", err)
	}
	if sources == nil {
		sources = []LogSource{}
	}
	c.JSON(http.StatusOK, gin.H{"sources": sources})
}

// CreateLogSource POST /sources
func (h *CloudSIEMHandler) CreateLogSource(c *gin.Context) {
	var body struct {
		Name          string      `json:"name" binding:"required"`
		SourceType    string      `json:"source_type" binding:"required"`
		Config        interface{} `json:"config"`
		DailyVolumeMB int64       `json:"daily_volume_mb"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if body.Config == nil {
		body.Config = map[string]interface{}{}
	}

	var id string
	err := h.pool.QueryRow(c.Request.Context(), `
		INSERT INTO siem_log_sources (name, source_type, config, daily_volume_mb)
		VALUES ($1, $2, $3, $4)
		RETURNING id
	`, body.Name, body.SourceType, body.Config, body.DailyVolumeMB).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id})
}

// UpdateLogSource PUT /sources/:id
func (h *CloudSIEMHandler) UpdateLogSource(c *gin.Context) {
	id := c.Param("id")
	if _, err := uuid.Parse(id); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	var body struct {
		Name          string      `json:"name"`
		SourceType    string      `json:"source_type"`
		Config        interface{} `json:"config"`
		DailyVolumeMB int64       `json:"daily_volume_mb"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	tag, err := h.pool.Exec(c.Request.Context(), `
		UPDATE siem_log_sources
		SET name=$1, source_type=$2, config=$3, daily_volume_mb=$4, updated_at=NOW()
		WHERE id=$5
	`, body.Name, body.SourceType, body.Config, body.DailyVolumeMB, id)
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

// DeleteLogSource DELETE /sources/:id
func (h *CloudSIEMHandler) DeleteLogSource(c *gin.Context) {
	id := c.Param("id")
	if _, err := uuid.Parse(id); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	tag, err := h.pool.Exec(c.Request.Context(), `DELETE FROM siem_log_sources WHERE id=$1`, id)
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

// ToggleLogSource POST /sources/:id/toggle
func (h *CloudSIEMHandler) ToggleLogSource(c *gin.Context) {
	id := c.Param("id")
	if _, err := uuid.Parse(id); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	var isActive bool
	err := h.pool.QueryRow(c.Request.Context(), `
		UPDATE siem_log_sources SET is_active = NOT is_active, updated_at=NOW()
		WHERE id=$1 RETURNING is_active
	`, id).Scan(&isActive)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"is_active": isActive})
}

// ListDetectionRules GET /rules
func (h *CloudSIEMHandler) ListDetectionRules(c *gin.Context) {
	rows, err := h.pool.Query(c.Request.Context(), `
		SELECT id, name, COALESCE(description,''), rule_type, query, severity,
		       time_window, threshold, is_active, match_count, last_matched,
		       created_at, updated_at
		FROM siem_detection_rules
		ORDER BY created_at DESC
		LIMIT 500
	`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	defer rows.Close()

	type DetectionRule struct {
		ID          string     `json:"id"`
		Name        string     `json:"name"`
		Description string     `json:"description"`
		RuleType    string     `json:"rule_type"`
		Query       string     `json:"query"`
		Severity    string     `json:"severity"`
		TimeWindow  int        `json:"time_window"`
		Threshold   *int       `json:"threshold"`
		IsActive    bool       `json:"is_active"`
		MatchCount  int        `json:"match_count"`
		LastMatched *time.Time `json:"last_matched"`
		CreatedAt   time.Time  `json:"created_at"`
		UpdatedAt   time.Time  `json:"updated_at"`
	}

	var rules []DetectionRule
	for rows.Next() {
		var r DetectionRule
		if err := rows.Scan(&r.ID, &r.Name, &r.Description, &r.RuleType, &r.Query,
			&r.Severity, &r.TimeWindow, &r.Threshold, &r.IsActive, &r.MatchCount,
			&r.LastMatched, &r.CreatedAt, &r.UpdatedAt); err != nil {
			slog.Warn("detection rule scan failed", "error", err)
			continue
		}
		rules = append(rules, r)
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if rules == nil {
		rules = []DetectionRule{}
	}
	c.JSON(http.StatusOK, gin.H{"rules": rules})
}

// CreateDetectionRule POST /rules
func (h *CloudSIEMHandler) CreateDetectionRule(c *gin.Context) {
	var body struct {
		Name        string `json:"name" binding:"required"`
		Description string `json:"description"`
		RuleType    string `json:"rule_type" binding:"required"`
		Query       string `json:"query" binding:"required"`
		Severity    string `json:"severity"`
		TimeWindow  int    `json:"time_window"`
		Threshold   *int   `json:"threshold"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if body.Severity == "" {
		body.Severity = "medium"
	}
	if body.TimeWindow == 0 {
		body.TimeWindow = 300
	}

	var id string
	err := h.pool.QueryRow(c.Request.Context(), `
		INSERT INTO siem_detection_rules (name, description, rule_type, query, severity, time_window, threshold)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id
	`, body.Name, body.Description, body.RuleType, body.Query, body.Severity, body.TimeWindow, body.Threshold).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id})
}

// UpdateDetectionRule PUT /rules/:id
func (h *CloudSIEMHandler) UpdateDetectionRule(c *gin.Context) {
	id := c.Param("id")
	if _, err := uuid.Parse(id); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	var body struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		RuleType    string `json:"rule_type"`
		Query       string `json:"query"`
		Severity    string `json:"severity"`
		TimeWindow  int    `json:"time_window"`
		Threshold   *int   `json:"threshold"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	tag, err := h.pool.Exec(c.Request.Context(), `
		UPDATE siem_detection_rules
		SET name=$1, description=$2, rule_type=$3, query=$4, severity=$5,
		    time_window=$6, threshold=$7, updated_at=NOW()
		WHERE id=$8
	`, body.Name, body.Description, body.RuleType, body.Query, body.Severity,
		body.TimeWindow, body.Threshold, id)
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

// DeleteDetectionRule DELETE /rules/:id
func (h *CloudSIEMHandler) DeleteDetectionRule(c *gin.Context) {
	id := c.Param("id")
	if _, err := uuid.Parse(id); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	tag, err := h.pool.Exec(c.Request.Context(), `DELETE FROM siem_detection_rules WHERE id=$1`, id)
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

// ToggleDetectionRule POST /rules/:id/toggle
func (h *CloudSIEMHandler) ToggleDetectionRule(c *gin.Context) {
	id := c.Param("id")
	if _, err := uuid.Parse(id); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	var isActive bool
	err := h.pool.QueryRow(c.Request.Context(), `
		UPDATE siem_detection_rules SET is_active = NOT is_active, updated_at=NOW()
		WHERE id=$1 RETURNING is_active
	`, id).Scan(&isActive)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"is_active": isActive})
}

// ListSavedQueries GET /queries
func (h *CloudSIEMHandler) ListSavedQueries(c *gin.Context) {
	rows, err := h.pool.Query(c.Request.Context(), `
		SELECT id, name, COALESCE(description,''), query, is_saved, run_count, created_by, created_at
		FROM siem_queries
		ORDER BY created_at DESC
		LIMIT 500
	`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	defer rows.Close()

	type SavedQuery struct {
		ID          string    `json:"id"`
		Name        string    `json:"name"`
		Description string    `json:"description"`
		Query       string    `json:"query"`
		IsSaved     bool      `json:"is_saved"`
		RunCount    int       `json:"run_count"`
		CreatedBy   *string   `json:"created_by"`
		CreatedAt   time.Time `json:"created_at"`
	}

	var queries []SavedQuery
	for rows.Next() {
		var q SavedQuery
		if err := rows.Scan(&q.ID, &q.Name, &q.Description, &q.Query, &q.IsSaved,
			&q.RunCount, &q.CreatedBy, &q.CreatedAt); err != nil {
			slog.Warn("saved query scan failed", "error", err)
			continue
		}
		queries = append(queries, q)
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if queries == nil {
		queries = []SavedQuery{}
	}
	c.JSON(http.StatusOK, gin.H{"queries": queries})
}

// SaveQuery POST /queries
func (h *CloudSIEMHandler) SaveQuery(c *gin.Context) {
	var body struct {
		Name        string `json:"name" binding:"required"`
		Description string `json:"description"`
		Query       string `json:"query" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID, _ := c.Get("user_id")
	userIDStr, _ := userID.(string)

	var id string
	var err error
	if userIDStr != "" {
		err = h.pool.QueryRow(c.Request.Context(), `
			INSERT INTO siem_queries (name, description, query, created_by)
			VALUES ($1, $2, $3, $4::uuid)
			RETURNING id
		`, body.Name, body.Description, body.Query, userIDStr).Scan(&id)
	} else {
		err = h.pool.QueryRow(c.Request.Context(), `
			INSERT INTO siem_queries (name, description, query)
			VALUES ($1, $2, $3)
			RETURNING id
		`, body.Name, body.Description, body.Query).Scan(&id)
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id})
}

// DeleteQuery DELETE /queries/:id
func (h *CloudSIEMHandler) DeleteQuery(c *gin.Context) {
	id := c.Param("id")
	if _, err := uuid.Parse(id); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	tag, err := h.pool.Exec(c.Request.Context(), `DELETE FROM siem_queries WHERE id=$1`, id)
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

// ExecuteQuery POST /queries/execute
// 実ログ検索エンジンは未実装。以前は乱数で生成した偽ログを本物として返していたが、
// セキュリティ製品で偽の検索結果を返すのは信頼性・誠実性の問題があるため、
// 準備中(503)を返すよう変更した。実装時はここに実ログストアへのクエリを配線する。
func (h *CloudSIEMHandler) ExecuteQuery(c *gin.Context) {
	var body struct {
		Query     string `json:"query" binding:"required"`
		TimeRange string `json:"time_range"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusServiceUnavailable, gin.H{
		"error": "SIEMクエリ実行エンジンは準備中です。実ログ検索バックエンドが未実装のため、現在クエリ結果は提供できません。",
	})
}

// GetStats GET /stats
func (h *CloudSIEMHandler) GetStats(c *gin.Context) {
	ctx := c.Request.Context()

	// Source counts by type
	typeRows, err := h.pool.Query(ctx, `
		SELECT source_type, COUNT(*) FROM siem_log_sources GROUP BY source_type
	`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	defer typeRows.Close()
	sourcesByType := map[string]int{}
	for typeRows.Next() {
		var t string
		var count int
		if err := typeRows.Scan(&t, &count); err == nil {
			sourcesByType[t] = count
		}
	}
	if err := typeRows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}

	// Rule counts
	var totalRules, activeRules int
	_ = h.pool.QueryRow(ctx, `SELECT COUNT(*), COUNT(*) FILTER (WHERE is_active) FROM siem_detection_rules`).
		Scan(&totalRules, &activeRules)

	// Daily volume total
	var totalVolumeMB int64
	_ = h.pool.QueryRow(ctx, `SELECT COALESCE(SUM(daily_volume_mb),0) FROM siem_log_sources WHERE is_active`).
		Scan(&totalVolumeMB)

	c.JSON(http.StatusOK, gin.H{
		"sources_by_type": sourcesByType,
		"total_rules":     totalRules,
		"active_rules":    activeRules,
		"total_volume_mb": totalVolumeMB,
	})
}
