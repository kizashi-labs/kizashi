package handlers

// UEBAAdvancedHandler provides additional UEBA endpoints that operate on the
// ueba_baselines and ueba_anomalies tables created in migration 121.
// The original UEBAHandler (ueba_handler.go) is preserved unchanged.
// These methods are promoted onto the existing UEBAHandler struct so the router
// only needs one handler type.

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
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
		// created_at is timestamptz; CreatedAt is a string for the JSON shape, and
		// pgx cannot put one in the other. Scanning it directly failed with
		// "cannot scan timestamptz (OID 1184) in binary format into *string" on
		// the first row, and pgx records that on the Rows, so rows.Err() below
		// turned it into a 500. This endpoint therefore worked only while
		// ueba_anomalies was empty — which is exactly the state the read-only
		// smoke tests leave it in. GetUserBehavior in this same file already
		// scans into time.Time and formats; this now matches it.
		var createdAt time.Time
		if err := rows.Scan(&a.ID, &a.Username, &a.AnomalyType, &a.Severity, &a.Score,
			&a.BaselineValue, &a.ActualValue, &a.Description, &a.Details,
			&a.Status, &a.ReviewedBy, &createdAt); err != nil {
			slog.Warn("UEBA異常の読み出しに失敗しました", "error", err)
			continue
		}
		a.CreatedAt = createdAt.UTC().Format(time.RFC3339)
		anomalies = append(anomalies, a)
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
	// A non-uuid reaches Postgres as 22P02, which the single error path below
	// used to report as "anomaly not found" — the same answer a real miss gets.
	if _, err := uuid.Parse(id); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "IDの形式が不正です"})
		return
	}

	var a Anomaly
	// Same timestamptz-into-string fault as ListAnomalies, and worse here: the
	// scan error was reported as 404, so an anomaly that exists was indexed as
	// one that does not.
	var createdAt time.Time
	err := h.Pool.QueryRow(ctx, `SELECT id, username, anomaly_type, severity, score,
		COALESCE(baseline_value,0), COALESCE(actual_value,0),
		COALESCE(description,''), details, status,
		COALESCE(reviewed_by::text,''), created_at
		FROM ueba_anomalies WHERE id = $1`, id).
		Scan(&a.ID, &a.Username, &a.AnomalyType, &a.Severity, &a.Score,
			&a.BaselineValue, &a.ActualValue, &a.Description, &a.Details,
			&a.Status, &a.ReviewedBy, &createdAt)
	if errors.Is(err, pgx.ErrNoRows) {
		c.JSON(http.StatusNotFound, gin.H{"error": "anomaly not found"})
		return
	}
	if err != nil {
		slog.Warn("UEBA異常の読み出しに失敗しました", "id", id, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	a.CreatedAt = createdAt.UTC().Format(time.RFC3339)
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
		// Same fault as ListAnomalies: updated_at is timestamptz and UpdatedAt is
		// a string, which pgx cannot bridge. The endpoint returned 500 as soon as
		// ueba_baselines held a row.
		var updatedAt time.Time
		if err := rows.Scan(&b.ID, &b.UserID, &b.Username, &b.MetricName,
			&b.BaselineValue, &b.StdDeviation, &b.SampleDays, &updatedAt); err != nil {
			slog.Warn("UEBAベースラインの読み出しに失敗しました", "error", err)
			continue
		}
		b.UpdatedAt = updatedAt.UTC().Format(time.RFC3339)
		baselines = append(baselines, b)
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
	if !ReadOK(c, h.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM ueba_anomalies
			WHERE username = $1 AND created_at >= NOW() - INTERVAL '30 days'`, username).Scan(&recentCount)) {
		return
	}

	// Risk score: sum of anomaly scores (capped at 100)
	var riskScore float64
	if !ReadOK(c, h.Pool.QueryRow(ctx, `SELECT COALESCE(SUM(score),0) FROM ueba_anomalies
			WHERE username = $1 AND status NOT IN ('false_positive') AND created_at >= NOW() - INTERVAL '30 days'`,
		username).Scan(&riskScore)) {
		return
	}
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
	if !ReadOK(c, h.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM ueba_anomalies`).Scan(&total)) {
		return
	}

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

	// users に username 列は無い（実在するのは email / full_name）。
	// insider_threat_handler.go の同じ結合と同様、以前はクエリ全体が
	// `column u.username does not exist` で失敗し、空配列が返っていた。
	// ua.username は OS ユーザ名でコンソールアカウントとは別の名前空間のため、
	// 結合キーが無い。UEBA 側の値だけで答える。
	rows, err := h.Pool.Query(ctx, `
		SELECT
			ua.username AS id,
			ua.username,
			'' AS email,
			LEAST(COALESCE(SUM(ua.score), 0), 100) AS risk_score,
			COUNT(*) AS anomalies,
			'' AS department,
			MAX(ua.created_at) AS last_seen
		FROM ueba_anomalies ua
		WHERE ua.status != 'false_positive'
		  AND ua.created_at >= NOW() - INTERVAL '30 days'
		GROUP BY ua.username
		ORDER BY risk_score DESC
		LIMIT $1
	`, limit)
	if err != nil {
		ReadFailure(c, err, []UebaUser{})
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
	if err := rows.Err(); err != nil {
		slog.Warn("ListUsers: 結果セットの読み取りが途中で終わりました。応答は不完全です", "error", err)
		c.JSON(http.StatusOK, []UebaUser{})
		return
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
		ReadFailure(c, err, []BehaviorEvent{})
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
	if err := rows.Err(); err != nil {
		slog.Warn("GetUserBehavior: 結果セットの読み取りが途中で終わりました。応答は不完全です", "error", err)
		c.JSON(http.StatusOK, []BehaviorEvent{})
		return
	}
	if events == nil {
		events = []BehaviorEvent{}
	}
	c.JSON(http.StatusOK, events)
}
