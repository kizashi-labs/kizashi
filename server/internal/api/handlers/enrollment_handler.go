package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

// EnrollmentHandler manages agent enrollment requests and rules.
type EnrollmentHandler struct {
	pool *pgxpool.Pool
	nc   *nats.Conn
}

// NewEnrollmentHandler creates a new EnrollmentHandler.
func NewEnrollmentHandler(pool *pgxpool.Pool, nc *nats.Conn) *EnrollmentHandler {
	return &EnrollmentHandler{pool: pool, nc: nc}
}

type enrollmentRequest struct {
	ID              string     `json:"id"`
	Hostname        string     `json:"hostname"`
	IPAddress       string     `json:"ip_address"`
	OSType          string     `json:"os_type"`
	OSVersion       string     `json:"os_version"`
	MachineID       string     `json:"machine_id"`
	EnrollmentToken string     `json:"enrollment_token"`
	Status          string     `json:"status"`
	AutoApproved    bool       `json:"auto_approved"`
	ApprovedBy      *string    `json:"approved_by,omitempty"`
	ApprovedAt      *time.Time `json:"approved_at,omitempty"`
	DeniedReason    *string    `json:"denied_reason,omitempty"`
	AgentID         *string    `json:"agent_id,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

type enrollmentRule struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	MatchField    string    `json:"match_field"`
	MatchPattern  string    `json:"match_pattern"`
	Action        string    `json:"action"`
	AssignGroupID *string   `json:"assign_group_id,omitempty"`
	AssignTags    []string  `json:"assign_tags"`
	Priority      int       `json:"priority"`
	Enabled       bool      `json:"enabled"`
	CreatedAt     time.Time `json:"created_at"`
}

// checkAutoApprove checks enrollment rules and returns true if the request should be auto-approved.
//
// 読めなかったときも false（＝手動承認へ）です。安全な方向に倒れるので
// 値を返し続けますが、黙ってはいけません。ルールを読めない間、自動承認を
// 設定してあるはずの端末がすべて手動待ちの列に積まれます。設定を疑って
// 見に行っても、ルールは正しく入っています。
func (h *EnrollmentHandler) checkAutoApprove(c *gin.Context, hostname, ipAddress string) bool {
	rows, err := h.pool.Query(c.Request.Context(),
		`SELECT match_field, match_pattern, action FROM enrollment_rules
		 WHERE enabled = true ORDER BY priority ASC`)
	if err != nil {
		slog.Error("enrollment: 自動承認ルールを読めないまま手動承認に倒しました",
			"hostname", hostname, "error", err)
		return false
	}
	defer rows.Close()

	for rows.Next() {
		var matchField, matchPattern, action string
		if scanErr := rows.Scan(&matchField, &matchPattern, &action); scanErr != nil {
			continue
		}
		var fieldValue string
		switch matchField {
		case "hostname":
			fieldValue = hostname
		case "ip_address":
			fieldValue = ipAddress
		default:
			continue
		}
		// Simple substring match
		if matchPattern != "" && containsPattern(fieldValue, matchPattern) {
			if action == "auto_approve" {
				return true
			}
		}
	}
	if err := rows.Err(); err != nil {
		slog.Error("enrollment: 自動承認ルールを読めないまま手動承認に倒しました",
			"hostname", hostname, "error", err)
		return false
	}
	return false
}

func containsPattern(value, pattern string) bool {
	// Simple glob-like match: if pattern ends with *, treat as prefix match
	if len(pattern) > 0 && pattern[len(pattern)-1] == '*' {
		prefix := pattern[:len(pattern)-1]
		return len(value) >= len(prefix) && value[:len(prefix)] == prefix
	}
	return value == pattern
}

// RequestEnrollment handles POST /enrollment/request (public endpoint).
func (h *EnrollmentHandler) RequestEnrollment(c *gin.Context) {
	var req struct {
		Hostname  string `json:"hostname" binding:"required"`
		IPAddress string `json:"ip_address" binding:"required"`
		OSType    string `json:"os_type" binding:"required"`
		OSVersion string `json:"os_version"`
		MachineID string `json:"machine_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: " + err.Error()})
		return
	}

	token := uuid.New().String()
	requestID := uuid.New().String()
	now := time.Now().UTC()
	status := "pending"
	autoApproved := false

	// Check auto-approve rules
	if h.checkAutoApprove(c, req.Hostname, req.IPAddress) {
		autoApproved = true
		status = "approved"
	}

	var agentID *string
	if autoApproved {
		// Create agent record
		newAgentID := uuid.New().String()
		// agents.ip_addresses is INET[], not a scalar ip_address, and its status
		// CHECK is (online|offline|isolated|error|inactive) — 'pending' belongs to
		// agent_enrollment_requests, which is what tracks approval. Writing the
		// scalar name and 'pending' made this INSERT fail twice over, so approved
		// enrollments never produced an agents row at all.
		_, err := h.pool.Exec(c.Request.Context(),
			`INSERT INTO agents (id, hostname, ip_addresses, os_type, os_version, status, created_at, updated_at)
			 VALUES ($1, $2, $3::inet[], $4, $5, 'offline', $6, $6)
			 ON CONFLICT DO NOTHING`,
			newAgentID, req.Hostname, enrollIPArray(req.IPAddress), req.OSType, req.OSVersion, now)
		if err != nil {
			slog.Warn("エンロールメント: エージェントレコードの作成に失敗", "error", err)
		} else {
			agentID = &newAgentID
		}
	}

	_, err := h.pool.Exec(c.Request.Context(),
		`INSERT INTO agent_enrollment_requests
		 (id, hostname, ip_address, os_type, os_version, machine_id, enrollment_token, status, auto_approved, agent_id, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $11)`,
		requestID, req.Hostname, req.IPAddress, req.OSType, req.OSVersion,
		req.MachineID, token, status, autoApproved, agentID, now)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}

	// Publish NATS event
	if h.nc != nil {
		payload, _ := json.Marshal(map[string]interface{}{
			"request_id": requestID,
			"hostname":   req.Hostname,
			"machine_id": req.MachineID,
			"status":     status,
		})
		if err := h.nc.Publish("agent.enrollment.requested", payload); err != nil {
			slog.Warn("NATS publish failed", "subject", "agent.enrollment.requested", "error", err)
		}
	}

	resp := gin.H{
		"request_id":    requestID,
		"token":         token,
		"status":        status,
		"auto_approved": autoApproved,
	}
	if agentID != nil {
		resp["agent_id"] = *agentID
	}
	c.JSON(http.StatusCreated, resp)
}

func (h *EnrollmentHandler) scanRequests(c *gin.Context, query string, args ...interface{}) ([]enrollmentRequest, error) {
	rows, err := h.pool.Query(c.Request.Context(), query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var requests []enrollmentRequest
	for rows.Next() {
		var r enrollmentRequest
		if scanErr := rows.Scan(
			&r.ID, &r.Hostname, &r.IPAddress, &r.OSType, &r.OSVersion, &r.MachineID,
			&r.EnrollmentToken, &r.Status, &r.AutoApproved, &r.ApprovedBy, &r.ApprovedAt,
			&r.DeniedReason, &r.AgentID, &r.CreatedAt, &r.UpdatedAt,
		); scanErr == nil {
			requests = append(requests, r)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return requests, nil
}

// ListRequests handles GET /admin/enrollment/requests.
func (h *EnrollmentHandler) ListRequests(c *gin.Context) {
	statusFilter := c.Query("status")

	const selectCols = `SELECT id, hostname, ip_address, os_type, os_version, machine_id,
		enrollment_token, status, auto_approved, approved_by, approved_at,
		denied_reason, agent_id, created_at, updated_at
		FROM agent_enrollment_requests`

	var requests []enrollmentRequest
	var err error
	if statusFilter != "" {
		requests, err = h.scanRequests(c, selectCols+` WHERE status = $1 ORDER BY created_at DESC`, statusFilter)
	} else {
		requests, err = h.scanRequests(c, selectCols+` ORDER BY created_at DESC`)
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if requests == nil {
		requests = []enrollmentRequest{}
	}
	c.JSON(http.StatusOK, gin.H{"requests": requests, "total": len(requests)})
}

// ApproveRequest handles POST /admin/enrollment/requests/:id/approve.
func (h *EnrollmentHandler) ApproveRequest(c *gin.Context) {
	id := c.Param("id")
	approverID, _ := c.Get("user_id")
	approverStr, _ := approverID.(string)
	now := time.Now().UTC()

	// Fetch request
	var req enrollmentRequest
	err := h.pool.QueryRow(c.Request.Context(),
		`SELECT id, hostname, ip_address, os_type, os_version, machine_id, status
		 FROM agent_enrollment_requests WHERE id = $1`, id).Scan(
		&req.ID, &req.Hostname, &req.IPAddress, &req.OSType, &req.OSVersion, &req.MachineID, &req.Status)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "enrollment request not found"})
		return
	}
	if req.Status != "pending" {
		c.JSON(http.StatusConflict, gin.H{"error": "request is not in pending status"})
		return
	}

	// Create agent record
	newAgentID := uuid.New().String()
	// Same column/constraint contract as the auto-approve path above.
	_, agentErr := h.pool.Exec(c.Request.Context(),
		`INSERT INTO agents (id, hostname, ip_addresses, os_type, os_version, status, created_at, updated_at)
		 VALUES ($1, $2, $3::inet[], $4, $5, 'offline', $6, $6)
		 ON CONFLICT DO NOTHING`,
		newAgentID, req.Hostname, enrollIPArray(req.IPAddress), req.OSType, req.OSVersion, now)
	if agentErr != nil {
		slog.Warn("エンロールメント承認: エージェントレコードの作成に失敗", "error", agentErr)
	}

	_, err = h.pool.Exec(c.Request.Context(),
		`UPDATE agent_enrollment_requests
		 SET status = 'approved', approved_by = $2::uuid, approved_at = $3, agent_id = $4, updated_at = $3
		 WHERE id = $1`,
		id, approverStr, now, newAgentID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}

	if h.nc != nil {
		payload, _ := json.Marshal(map[string]interface{}{
			"request_id":  id,
			"agent_id":    newAgentID,
			"approved_by": approverStr,
		})
		if err := h.nc.Publish("agent.enrollment.approved", payload); err != nil {
			slog.Warn("NATS publish failed", "subject", "agent.enrollment.approved", "error", err)
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"status":   "approved",
		"agent_id": newAgentID,
	})
}

// DenyRequest handles POST /admin/enrollment/requests/:id/deny.
func (h *EnrollmentHandler) DenyRequest(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Reason string `json:"reason"`
	}
	_ = c.ShouldBindJSON(&req)
	now := time.Now().UTC()

	_, err := h.pool.Exec(c.Request.Context(),
		`UPDATE agent_enrollment_requests
		 SET status = 'denied', denied_reason = $2, updated_at = $3
		 WHERE id = $1`,
		id, req.Reason, now)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "denied"})
}

// ListRules handles GET /admin/enrollment/rules.
func (h *EnrollmentHandler) ListRules(c *gin.Context) {
	rows, err := h.pool.Query(c.Request.Context(),
		`SELECT id, name, match_field, match_pattern, action, assign_group_id,
		        assign_tags, priority, enabled, created_at
		 FROM enrollment_rules ORDER BY priority ASC`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	defer rows.Close()

	var rules []enrollmentRule
	for rows.Next() {
		var r enrollmentRule
		var tagsJSON []byte
		if scanErr := rows.Scan(
			&r.ID, &r.Name, &r.MatchField, &r.MatchPattern, &r.Action,
			&r.AssignGroupID, &tagsJSON, &r.Priority, &r.Enabled, &r.CreatedAt,
		); scanErr == nil {
			if tagsJSON != nil {
				_ = json.Unmarshal(tagsJSON, &r.AssignTags)
			}
			if r.AssignTags == nil {
				r.AssignTags = []string{}
			}
			rules = append(rules, r)
		}
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if rules == nil {
		rules = []enrollmentRule{}
	}
	c.JSON(http.StatusOK, gin.H{"rules": rules, "total": len(rules)})
}

// CreateRule handles POST /admin/enrollment/rules.
func (h *EnrollmentHandler) CreateRule(c *gin.Context) {
	var req struct {
		Name          string   `json:"name" binding:"required"`
		MatchField    string   `json:"match_field"`
		MatchPattern  string   `json:"match_pattern" binding:"required"`
		Action        string   `json:"action"`
		AssignGroupID *string  `json:"assign_group_id"`
		AssignTags    []string `json:"assign_tags"`
		Priority      int      `json:"priority"`
		Enabled       *bool    `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: " + err.Error()})
		return
	}

	if req.MatchField == "" {
		req.MatchField = "hostname"
	}
	if req.Action == "" {
		req.Action = "auto_approve"
	}
	if req.Priority == 0 {
		req.Priority = 100
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	if req.AssignTags == nil {
		req.AssignTags = []string{}
	}

	tagsJSON, _ := json.Marshal(req.AssignTags)
	id := uuid.New().String()
	now := time.Now().UTC()

	_, err := h.pool.Exec(c.Request.Context(),
		`INSERT INTO enrollment_rules (id, name, match_field, match_pattern, action, assign_group_id, assign_tags, priority, enabled, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		id, req.Name, req.MatchField, req.MatchPattern, req.Action,
		req.AssignGroupID, tagsJSON, req.Priority, enabled, now)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"id":            id,
		"name":          req.Name,
		"match_field":   req.MatchField,
		"match_pattern": req.MatchPattern,
		"action":        req.Action,
		"priority":      req.Priority,
		"enabled":       enabled,
		"created_at":    now,
	})
}

// DeleteRule handles DELETE /admin/enrollment/rules/:id.
func (h *EnrollmentHandler) DeleteRule(c *gin.Context) {
	id := c.Param("id")
	ct, err := h.pool.Exec(c.Request.Context(),
		`DELETE FROM enrollment_rules WHERE id = $1`, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if ct.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "rule not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}

// enrollIPArray wraps a single enrollment IP for agents.ip_addresses (INET[]).
// An empty string is returned as nil rather than [""], because Postgres rejects
// the empty string as an inet value and would fail the whole INSERT.
func enrollIPArray(ip string) []string {
	if strings.TrimSpace(ip) == "" {
		return nil
	}
	return []string{ip}
}
