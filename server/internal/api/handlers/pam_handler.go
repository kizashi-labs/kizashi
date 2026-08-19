package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PAMHandler provides Privileged Access Management endpoints.
type PAMHandler struct {
	pool *pgxpool.Pool
}

// NewPAMHandler creates a new PAMHandler.
func NewPAMHandler(pool *pgxpool.Pool) *PAMHandler {
	return &PAMHandler{pool: pool}
}

func (h *PAMHandler) requestsTableExists(c *gin.Context) bool {
	return tableIsThere(c.Request.Context(), h.pool, "pam_access_requests")
}

func (h *PAMHandler) sessionsTableExists(c *gin.Context) bool {
	return tableIsThere(c.Request.Context(), h.pool, "pam_sessions")
}

// ListRequests — GET /pam/requests
func (h *PAMHandler) ListRequests(c *gin.Context) {
	if !h.requestsTableExists(c) {
		c.JSON(http.StatusOK, gin.H{"requests": []interface{}{}, "total": 0})
		return
	}

	ctx := c.Request.Context()
	statusFilter := c.Query("status")
	requesterFilter := c.Query("requester_id")

	query := `SELECT id, requester_id, target_resource, resource_type, justification,
		access_level, duration_minutes, status, approved_by, approved_at, expires_at,
		denied_reason, created_at, updated_at
		FROM pam_access_requests WHERE 1=1`
	args := []interface{}{}
	argIdx := 1

	if statusFilter != "" {
		query += " AND status = $" + strconv.Itoa(argIdx)
		args = append(args, statusFilter)
		argIdx++
	}
	if requesterFilter != "" {
		query += " AND requester_id::text = $" + strconv.Itoa(argIdx)
		args = append(args, requesterFilter)
		argIdx++
	}
	query += " ORDER BY created_at DESC LIMIT 100"

	rows, err := h.pool.Query(ctx, query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	defer rows.Close()

	type PAMRequest struct {
		ID              string  `json:"id"`
		RequesterID     string  `json:"requester_id"`
		TargetResource  string  `json:"target_resource"`
		ResourceType    string  `json:"resource_type"`
		Justification   string  `json:"justification"`
		AccessLevel     string  `json:"access_level"`
		DurationMinutes int     `json:"duration_minutes"`
		Status          string  `json:"status"`
		ApprovedBy      *string `json:"approved_by"`
		ApprovedAt      *string `json:"approved_at"`
		ExpiresAt       *string `json:"expires_at"`
		DeniedReason    *string `json:"denied_reason"`
		CreatedAt       string  `json:"created_at"`
		UpdatedAt       string  `json:"updated_at"`
	}

	var requests []PAMRequest
	for rows.Next() {
		var r PAMRequest
		var approvedAt, expiresAt *time.Time
		var createdAt, updatedAt time.Time
		if err := rows.Scan(
			&r.ID, &r.RequesterID, &r.TargetResource, &r.ResourceType, &r.Justification,
			&r.AccessLevel, &r.DurationMinutes, &r.Status, &r.ApprovedBy, &approvedAt, &expiresAt,
			&r.DeniedReason, &createdAt, &updatedAt,
		); err != nil {
			continue
		}
		r.CreatedAt = createdAt.Format(time.RFC3339)
		r.UpdatedAt = updatedAt.Format(time.RFC3339)
		if approvedAt != nil {
			s := approvedAt.Format(time.RFC3339)
			r.ApprovedAt = &s
		}
		if expiresAt != nil {
			s := expiresAt.Format(time.RFC3339)
			r.ExpiresAt = &s
		}
		requests = append(requests, r)
	}
	if err := rows.Err(); err != nil {
		slog.Error("rows.Err: 結果の読み出しが途中で失敗しました", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}

	if requests == nil {
		requests = []PAMRequest{}
	}
	c.JSON(http.StatusOK, gin.H{"requests": requests, "total": len(requests)})
}

// GetRequest — GET /pam/requests/:id
func (h *PAMHandler) GetRequest(c *gin.Context) {
	if !h.requestsTableExists(c) {
		c.JSON(http.StatusNotFound, gin.H{"error": "table not found"})
		return
	}

	ctx := c.Request.Context()
	id := c.Param("id")
	if !isValidUUID(id) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id format"})
		return
	}

	row := h.pool.QueryRow(ctx, `
		SELECT id, requester_id, target_resource, resource_type, justification,
		access_level, duration_minutes, status, approved_by, approved_at, expires_at,
		denied_reason, created_at, updated_at
		FROM pam_access_requests WHERE id = $1`, id)

	var r struct {
		ID              string  `json:"id"`
		RequesterID     string  `json:"requester_id"`
		TargetResource  string  `json:"target_resource"`
		ResourceType    string  `json:"resource_type"`
		Justification   string  `json:"justification"`
		AccessLevel     string  `json:"access_level"`
		DurationMinutes int     `json:"duration_minutes"`
		Status          string  `json:"status"`
		ApprovedBy      *string `json:"approved_by"`
		ApprovedAt      *string `json:"approved_at"`
		ExpiresAt       *string `json:"expires_at"`
		DeniedReason    *string `json:"denied_reason"`
		CreatedAt       string  `json:"created_at"`
		UpdatedAt       string  `json:"updated_at"`
	}

	var approvedAt, expiresAt *time.Time
	var createdAt, updatedAt time.Time
	if err := row.Scan(
		&r.ID, &r.RequesterID, &r.TargetResource, &r.ResourceType, &r.Justification,
		&r.AccessLevel, &r.DurationMinutes, &r.Status, &r.ApprovedBy, &approvedAt, &expiresAt,
		&r.DeniedReason, &createdAt, &updatedAt,
	); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "request not found"})
		return
	}

	r.CreatedAt = createdAt.Format(time.RFC3339)
	r.UpdatedAt = updatedAt.Format(time.RFC3339)
	if approvedAt != nil {
		s := approvedAt.Format(time.RFC3339)
		r.ApprovedAt = &s
	}
	if expiresAt != nil {
		s := expiresAt.Format(time.RFC3339)
		r.ExpiresAt = &s
	}

	c.JSON(http.StatusOK, r)
}

// CreateRequest — POST /pam/requests
func (h *PAMHandler) CreateRequest(c *gin.Context) {
	if !h.requestsTableExists(c) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "PAM tables not initialized"})
		return
	}

	var body struct {
		TargetResource  string `json:"target_resource" binding:"required"`
		ResourceType    string `json:"resource_type"`
		Justification   string `json:"justification" binding:"required"`
		AccessLevel     string `json:"access_level"`
		DurationMinutes int    `json:"duration_minutes"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if body.Justification == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "justification is required"})
		return
	}
	if body.DurationMinutes < 1 || body.DurationMinutes > 480 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "duration_minutes must be between 1 and 480"})
		return
	}
	if body.ResourceType == "" {
		body.ResourceType = "server"
	}
	if body.AccessLevel == "" {
		body.AccessLevel = "read"
	}

	requesterID, _ := c.Get("user_id")
	requesterIDStr, _ := requesterID.(string)
	if requesterIDStr == "" {
		requesterIDStr = "00000000-0000-0000-0000-000000000000"
	}

	ctx := c.Request.Context()
	var id string
	err := h.pool.QueryRow(ctx, `
		INSERT INTO pam_access_requests
		(requester_id, target_resource, resource_type, justification, access_level, duration_minutes, status)
		VALUES ($1, $2, $3, $4, $5, $6, 'pending')
		RETURNING id`,
		requesterIDStr, body.TargetResource, body.ResourceType, body.Justification,
		body.AccessLevel, body.DurationMinutes,
	).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"id": id, "status": "pending"})
}

// ApproveRequest — POST /pam/requests/:id/approve
func (h *PAMHandler) ApproveRequest(c *gin.Context) {
	if !h.requestsTableExists(c) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "PAM tables not initialized"})
		return
	}

	ctx := c.Request.Context()
	id := c.Param("id")
	if !isValidUUID(id) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id format"})
		return
	}

	approverID, _ := c.Get("user_id")
	approverIDStr, _ := approverID.(string)
	if approverIDStr == "" {
		approverIDStr = "00000000-0000-0000-0000-000000000000"
	}

	// Get the request duration
	var durationMinutes int
	var status string
	err := h.pool.QueryRow(ctx,
		`SELECT duration_minutes, status FROM pam_access_requests WHERE id = $1`, id,
	).Scan(&durationMinutes, &status)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "request not found"})
		return
	}
	if status != "pending" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "request is not pending"})
		return
	}

	now := time.Now().UTC()
	expiresAt := now.Add(time.Duration(durationMinutes) * time.Minute)

	_, err = h.pool.Exec(ctx, `
		UPDATE pam_access_requests
		SET status='approved', approved_by=$1, approved_at=$2, expires_at=$3, updated_at=NOW()
		WHERE id=$4`,
		approverIDStr, now, expiresAt, id,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}

	// Create PAM session
	tokenBytes := make([]byte, 32)
	// crypto/rand.Read は Go 1.24 以降エラーを返しません（取得できないときは
	// panic します）。エラー分岐を書いても到達しないので書きません。
	_, _ = rand.Read(tokenBytes)
	sessionToken := hex.EncodeToString(tokenBytes)

	var sessionID string
	if h.sessionsTableExists(c) {
		err = h.pool.QueryRow(ctx, `
			INSERT INTO pam_sessions (request_id, session_token, is_active)
			VALUES ($1, $2, TRUE)
			RETURNING id`,
			id, sessionToken,
		).Scan(&sessionID)
		if err != nil {
			// 以前は sessionID = "" として、承認と一緒にトークンを返して
			// いました。行が入っていないので、そのトークンに対応する
			// セッションはどこにもありません。申請者は特権アクセスを
			// 受け取ったつもりで、使えない鍵を持ちます。
			slog.Error("pam: セッションを作成できませんでした", "request", id, "error", err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "承認は記録しましたが、特権セッションを作成できませんでした。もう一度承認してください",
			})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"status":        "approved",
		"expires_at":    expiresAt.Format(time.RFC3339),
		"session_id":    sessionID,
		"session_token": sessionToken,
	})
}

// DenyRequest — POST /pam/requests/:id/deny
func (h *PAMHandler) DenyRequest(c *gin.Context) {
	if !h.requestsTableExists(c) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "PAM tables not initialized"})
		return
	}

	ctx := c.Request.Context()
	id := c.Param("id")

	var body struct {
		Reason string `json:"reason"`
	}
	_ = c.ShouldBindJSON(&body)

	var status string
	err := h.pool.QueryRow(ctx,
		`SELECT status FROM pam_access_requests WHERE id = $1`, id,
	).Scan(&status)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "request not found"})
		return
	}
	if status != "pending" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "request is not pending"})
		return
	}

	_, err = h.pool.Exec(ctx, `
		UPDATE pam_access_requests
		SET status='denied', denied_reason=$1, updated_at=NOW()
		WHERE id=$2`,
		body.Reason, id,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "denied"})
}

// ListSessions — GET /pam/sessions
func (h *PAMHandler) ListSessions(c *gin.Context) {
	if !h.sessionsTableExists(c) {
		c.JSON(http.StatusOK, gin.H{"sessions": []interface{}{}, "total": 0})
		return
	}

	ctx := c.Request.Context()

	rows, err := h.pool.Query(ctx, `
		SELECT s.id, s.request_id, s.session_token, s.started_at, s.ended_at,
		       s.commands_executed, s.recording_path, s.is_active,
		       r.target_resource, r.requester_id
		FROM pam_sessions s
		JOIN pam_access_requests r ON r.id = s.request_id
		ORDER BY s.started_at DESC
		LIMIT 100`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	defer rows.Close()

	type PAMSession struct {
		ID               string  `json:"id"`
		RequestID        string  `json:"request_id"`
		SessionToken     string  `json:"session_token"`
		StartedAt        string  `json:"started_at"`
		EndedAt          *string `json:"ended_at"`
		CommandsExecuted int     `json:"commands_executed"`
		RecordingPath    *string `json:"recording_path"`
		IsActive         bool    `json:"is_active"`
		TargetResource   string  `json:"target_resource"`
		RequesterID      string  `json:"requester_id"`
	}

	var sessions []PAMSession
	for rows.Next() {
		var s PAMSession
		var startedAt time.Time
		var endedAt *time.Time
		if err := rows.Scan(
			&s.ID, &s.RequestID, &s.SessionToken, &startedAt, &endedAt,
			&s.CommandsExecuted, &s.RecordingPath, &s.IsActive,
			&s.TargetResource, &s.RequesterID,
		); err != nil {
			continue
		}
		s.StartedAt = startedAt.Format(time.RFC3339)
		if endedAt != nil {
			t := endedAt.Format(time.RFC3339)
			s.EndedAt = &t
		}
		sessions = append(sessions, s)
	}
	if err := rows.Err(); err != nil {
		slog.Error("rows.Err: 結果の読み出しが途中で失敗しました", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}

	if sessions == nil {
		sessions = []PAMSession{}
	}
	c.JSON(http.StatusOK, gin.H{"sessions": sessions, "total": len(sessions)})
}

// EndSession — POST /pam/sessions/:id/end
func (h *PAMHandler) EndSession(c *gin.Context) {
	if !h.sessionsTableExists(c) {
		c.JSON(http.StatusNotFound, gin.H{"error": "sessions table not found"})
		return
	}

	ctx := c.Request.Context()
	id := c.Param("id")

	result, err := h.pool.Exec(ctx, `
		UPDATE pam_sessions
		SET ended_at=NOW(), is_active=FALSE
		WHERE id=$1 AND is_active=TRUE`, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "active session not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ended"})
}

// GetStats — GET /pam/stats
func (h *PAMHandler) GetStats(c *gin.Context) {
	ctx := c.Request.Context()

	type PAMStats struct {
		PendingCount    int     `json:"pending_count"`
		ApprovedToday   int     `json:"approved_today"`
		AvgApprovalTime float64 `json:"avg_approval_time_minutes"`
		ActiveSessions  int     `json:"active_sessions"`
	}

	var stats PAMStats

	if h.requestsTableExists(c) {
		if !ReadOK(c, h.pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM pam_access_requests WHERE status='pending'`,
		).Scan(&stats.PendingCount)) {
			return
		}

		if !ReadOK(c, h.pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM pam_access_requests WHERE status='approved' AND DATE(approved_at)=CURRENT_DATE`,
		).Scan(&stats.ApprovedToday)) {
			return
		}

		if !ReadOK(c, h.pool.QueryRow(ctx, `
				SELECT COALESCE(AVG(EXTRACT(EPOCH FROM (approved_at - created_at))/60), 0)
				FROM pam_access_requests
				WHERE status='approved' AND approved_at IS NOT NULL`,
		).Scan(&stats.AvgApprovalTime)) {
			return
		}
	}

	if h.sessionsTableExists(c) {
		if !ReadOK(c, h.pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM pam_sessions WHERE is_active=TRUE`,
		).Scan(&stats.ActiveSessions)) {
			return
		}
	}

	c.JSON(http.StatusOK, stats)
}
