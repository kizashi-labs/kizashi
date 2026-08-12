package handlers

// UEBAAdvancedHandler provides additional UEBA endpoints that operate on the
// ueba_baselines and ueba_anomalies tables created in migration 121.
// The original UEBAHandler (ueba_handler.go) is preserved unchanged.
// These methods are promoted onto the existing UEBAHandler struct so the router
// only needs one handler type.

import (
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

// ListAnomalies GET /anomalies
func (h *UEBAHandler) ListAnomalies(c *gin.Context) {
	ctx := c.Request.Context()
	username := c.Query("username")
	severity := c.Query("severity")
	status := c.Query("status")
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if limit < 1 || limit > 200 {
		limit = 50
	}

	query := `SELECT id, username, anomaly_type, severity, score,
		COALESCE(baseline_value,0), COALESCE(actual_value,0),
		COALESCE(description,''), details, status,
		COALESCE(reviewed_by::text,''), created_at
		FROM ueba_anomalies WHERE 1=1`
	args := []interface{}{}
	n := 1

	if username != "" {
		query += " AND username = $" + strconv.Itoa(n)
		args = append(args, username)
		n++
	}
	if severity != "" {
		query += " AND severity = $" + strconv.Itoa(n)
		args = append(args, severity)
		n++
	}
	if status != "" {
		query += " AND status = $" + strconv.Itoa(n)
		args = append(args, status)
		n++
	}
	query += " ORDER BY created_at DESC LIMIT $" + strconv.Itoa(n) + " OFFSET $" + strconv.Itoa(n+1)
	args = append(args, limit, offset)

	rows, err := h.Pool.Query(ctx, query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	defer rows.Close()

	type Anomaly struct {
		ID            string      `json:"id"`
		Username      string      `json:"username"`
		AnomalyType   string      `json:"anomaly_type"`
		Severity      string      `json:"severity"`
		Score         float64     `json:"score"`
		BaselineValue float64     `json:"baseline_value"`
		ActualValue   float64     `json:"actual_value"`
		Description   string      `json:"description"`
		Details       interface{} `json:"details"`
		Status        string      `json:"status"`
		ReviewedBy    string      `json:"reviewed_by,omitempty"`
		CreatedAt     string      `json:"created_at"`
	}
	anomalies := []Anomaly{}
	for rows.Next() {
		var a Anomaly
		if rows.Scan(&a.ID, &a.Username, &a.AnomalyType, &a.Severity, &a.Score,
			&a.BaselineValue, &a.ActualValue, &a.Description, &a.Details,
			&a.Status, &a.ReviewedBy, &a.CreatedAt) == nil {
			anomalies = append(anomalies, a)
		}
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"anomalies": anomalies, "limit": limit, "offset": offset})
}

// GetAnomaly GET /anomalies/:id
func (h *UEBAHandler) GetAnomaly(c *gin.Context) {
	ctx := c.Request.Context()
	id := c.Param("id")

	type Anomaly struct {
		ID            string      `json:"id"`
		Username      string      `json:"username"`
		AnomalyType   string      `json:"anomaly_type"`
		Severity      string      `json:"severity"`
		Score         float64     `json:"score"`
		BaselineValue float64     `json:"baseline_value"`
		ActualValue   float64     `json:"actual_value"`
		Description   string      `json:"description"`
		Details       interface{} `json:"details"`
		Status        string      `json:"status"`
		ReviewedBy    string      `json:"reviewed_by,omitempty"`
		CreatedAt     string      `json:"created_at"`
	}
	var a Anomaly
	err := h.Pool.QueryRow(ctx, `SELECT id, username, anomaly_type, severity, score,
		COALESCE(baseline_value,0), COALESCE(actual_value,0),
		COALESCE(description,''), details, status,
		COALESCE(reviewed_by::text,''), created_at
		FROM ueba_anomalies WHERE id = $1`, id).
		Scan(&a.ID, &a.Username, &a.AnomalyType, &a.Severity, &a.Score,
			&a.BaselineValue, &a.ActualValue, &a.Description, &a.Details,
			&a.Status, &a.ReviewedBy, &a.CreatedAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "anomaly not found"})
		return
	}
	c.JSON(http.StatusOK, a)
}

// UpdateAnomalyStatus PATCH /anomalies/:id/status
func (h *UEBAHandler) UpdateAnomalyStatus(c *gin.Context) {
	ctx := c.Request.Context()
	id := c.Param("id")
	var req struct {
		Status string `json:"status" binding:"required"`
		Notes  string `json:"notes"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	userID, _ := c.Get("user_id")
	tag, err := h.Pool.Exec(ctx, `UPDATE ueba_anomalies SET status = $1, reviewed_by = $2::uuid WHERE id = $3`,
		req.Status, userID, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "anomaly not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// ListBaselines GET /baselines
func (h *UEBAHandler) ListBaselines(c *gin.Context) {
	ctx := c.Request.Context()
	username := c.Query("username")

	query := `SELECT id, COALESCE(user_id::text,''), username, metric_name,
		baseline_value, std_deviation, sample_days, updated_at
		FROM ueba_baselines WHERE 1=1`
	args := []interface{}{}
	n := 1

	if username != "" {
		query += " AND username = $" + strconv.Itoa(n)
		args = append(args, username)
		n++
	}
	_ = n
	query += " ORDER BY username, metric_name"

	rows, err := h.Pool.Query(ctx, query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	defer rows.Close()

	type Baseline struct {
		ID            string  `json:"id"`
		UserID        string  `json:"user_id,omitempty"`
		Username      string  `json:"username"`
		MetricName    string  `json:"metric_name"`
		BaselineValue float64 `json:"baseline_value"`
		StdDeviation  float64 `json:"std_deviation"`
		SampleDays    int     `json:"sample_days"`
		UpdatedAt     string  `json:"updated_at"`
	}
	baselines := []Baseline{}
	for rows.Next() {
		var b Baseline
		if rows.Scan(&b.ID, &b.UserID, &b.Username, &b.MetricName,
			&b.BaselineValue, &b.StdDeviation, &b.SampleDays, &b.UpdatedAt) == nil {
			baselines = append(baselines, b)
		}
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"baselines": baselines})
}

// GetUserProfile GET /users/:username
func (h *UEBAHandler) GetUserProfile(c *gin.Context) {
	ctx := c.Request.Context()
	username := c.Param("username")

	// Baselines
	rows, err := h.Pool.Query(ctx, `SELECT metric_name, baseline_value, std_deviation
		FROM ueba_baselines WHERE username = $1`, username)
	baselines := map[string]interface{}{}
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var name string
			var val, std float64
			if rows.Scan(&name, &val, &std) == nil {
				baselines[name] = gin.H{"baseline": val, "std_deviation": std}
			}
		}
		if err := rows.Err(); err != nil {
			slog.Warn("ueba baselines iteration failed", "error", err)
		}
	}

	// Recent anomaly count (last 30 days)
	var recentCount int
	_ = h.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM ueba_anomalies
		WHERE username = $1 AND created_at >= NOW() - INTERVAL '30 days'`, username).Scan(&recentCount)

	// Risk score: sum of anomaly scores (capped at 100)
	var riskScore float64
	_ = h.Pool.QueryRow(ctx, `SELECT COALESCE(SUM(score),0) FROM ueba_anomalies
		WHERE username = $1 AND status NOT IN ('false_positive') AND created_at >= NOW() - INTERVAL '30 days'`,
		username).Scan(&riskScore)
	if riskScore > 100 {
		riskScore = 100
	}

	// Top anomaly types
	type TypeCount struct {
		AnomalyType string `json:"anomaly_type"`
		Count       int    `json:"count"`
	}
	topTypes := []TypeCount{}
	rows2, err := h.Pool.Query(ctx, `SELECT anomaly_type, COUNT(*) FROM ueba_anomalies
		WHERE username = $1 GROUP BY anomaly_type ORDER BY COUNT(*) DESC LIMIT 5`, username)
	if err == nil {
		defer rows2.Close()
		for rows2.Next() {
			var t TypeCount
			if rows2.Scan(&t.AnomalyType, &t.Count) == nil {
				topTypes = append(topTypes, t)
			}
		}
		if err := rows2.Err(); err != nil {
			slog.Warn("ueba topTypes iteration failed", "error", err)
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"username":          username,
		"baselines":         baselines,
		"recent_anomalies":  recentCount,
		"risk_score":        riskScore,
		"top_anomaly_types": topTypes,
	})
}

// GetStats GET /stats (UEBA)
func (h *UEBAHandler) GetStats(c *gin.Context) {
	ctx := c.Request.Context()

	type TypeSev struct {
		AnomalyType string `json:"anomaly_type"`
		Severity    string `json:"severity"`
		Count       int    `json:"count"`
	}
	bySev := []TypeSev{}
	rows, err := h.Pool.Query(ctx, `SELECT anomaly_type, severity, COUNT(*) FROM ueba_anomalies
		GROUP BY anomaly_type, severity ORDER BY COUNT(*) DESC LIMIT 20`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var t TypeSev
			if rows.Scan(&t.AnomalyType, &t.Severity, &t.Count) == nil {
				bySev = append(bySev, t)
			}
		}
		if err := rows.Err(); err != nil {
			slog.Warn("ueba bySev iteration failed", "error", err)
		}
	}

	type UserRisk struct {
		Username  string  `json:"username"`
		RiskScore float64 `json:"risk_score"`
		Anomalies int     `json:"anomalies"`
	}
	topUsers := []UserRisk{}
	rows2, err := h.Pool.Query(ctx, `SELECT username, LEAST(SUM(score),100), COUNT(*)
		FROM ueba_anomalies
		WHERE status NOT IN ('false_positive') AND created_at >= NOW() - INTERVAL '30 days'
		GROUP BY username ORDER BY SUM(score) DESC LIMIT 10`)
	if err == nil {
		defer rows2.Close()
		for rows2.Next() {
			var u UserRisk
			if rows2.Scan(&u.Username, &u.RiskScore, &u.Anomalies) == nil {
				topUsers = append(topUsers, u)
			}
		}
		if err := rows2.Err(); err != nil {
			slog.Warn("row iteration error", "error", err)
		}
	}

	var total int
	_ = h.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM ueba_anomalies`).Scan(&total)

	c.JSON(http.StatusOK, gin.H{
		"total":            total,
		"by_type_severity": bySev,
		"top_risky_users":  topUsers,
	})
}

// ListUsers returns all users with UEBA risk scores.
// Supports ?sort=risk_score&limit=N
// GET /api/v1/ueba/users
func (h *UEBAHandler) ListUsers(c *gin.Context) {
	ctx := c.Request.Context()
	limit := 100
	if l := c.Query("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > 500 {
		limit = 500
	}

	type UebaUser struct {
		ID         string  `json:"id"`
		Username   string  `json:"username"`
		Email      string  `json:"email"`
		RiskScore  float64 `json:"risk_score"`
		Anomalies  int     `json:"anomalies"`
		Department string  `json:"department"`
		LastSeen   string  `json:"last_seen"`
	}

	rows, err := h.Pool.Query(ctx, `
		SELECT
			COALESCE(u.id::text, ua.username) AS id,
			ua.username,
			COALESCE(u.email, '') AS email,
			LEAST(COALESCE(SUM(ua.score), 0), 100) AS risk_score,
			COUNT(*) AS anomalies,
			COALESCE(u.role, '') AS department,
			MAX(ua.created_at) AS last_seen
		FROM ueba_anomalies ua
		LEFT JOIN users u ON u.username = ua.username
		WHERE ua.status != 'false_positive'
		  AND ua.created_at >= NOW() - INTERVAL '30 days'
		GROUP BY ua.username, u.id, u.email, u.role
		ORDER BY risk_score DESC
		LIMIT $1
	`, limit)
	if err != nil {
		c.JSON(http.StatusOK, []UebaUser{})
		return
	}
	defer rows.Close()

	var users []UebaUser
	for rows.Next() {
		var u UebaUser
		var lastSeen time.Time
		if rows.Scan(&u.ID, &u.Username, &u.Email, &u.RiskScore, &u.Anomalies, &u.Department, &lastSeen) != nil {
			continue
		}
		u.LastSeen = lastSeen.Format(time.RFC3339)
		users = append(users, u)
	}
	if users == nil {
		users = []UebaUser{}
	}
	c.JSON(http.StatusOK, users)
}

// GetUserBehavior returns behavior events for a specific user.
// GET /api/v1/ueba/users/:id/behavior
func (h *UEBAHandler) GetUserBehavior(c *gin.Context) {
	ctx := c.Request.Context()
	userID := c.Param("id")

	type BehaviorEvent struct {
		ID          string  `json:"id"`
		AnomalyType string  `json:"anomaly_type"`
		Score       float64 `json:"score"`
		Severity    string  `json:"severity"`
		Description string  `json:"description"`
		CreatedAt   string  `json:"created_at"`
	}

	rows, err := h.Pool.Query(ctx, `
		SELECT id::text, anomaly_type, score, severity, COALESCE(description,''), created_at
		FROM ueba_anomalies
		WHERE (id::text = $1 OR username = $1)
		  AND status != 'false_positive'
		ORDER BY created_at DESC LIMIT 50
	`, userID)
	if err != nil {
		c.JSON(http.StatusOK, []BehaviorEvent{})
		return
	}
	defer rows.Close()

	var events []BehaviorEvent
	for rows.Next() {
		var e BehaviorEvent
		var ts time.Time
		if rows.Scan(&e.ID, &e.AnomalyType, &e.Score, &e.Severity, &e.Description, &ts) != nil {
			continue
		}
		e.CreatedAt = ts.Format(time.RFC3339)
		events = append(events, e)
	}
	if events == nil {
		events = []BehaviorEvent{}
	}
	c.JSON(http.StatusOK, events)
}
