package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AutonomousPolicyHandler handles autonomous response policy endpoints.
type AutonomousPolicyHandler struct {
	pool *pgxpool.Pool
}

// NewAutonomousPolicyHandler creates a new AutonomousPolicyHandler.
func NewAutonomousPolicyHandler(pool *pgxpool.Pool) *AutonomousPolicyHandler {
	return &AutonomousPolicyHandler{pool: pool}
}

func (h *AutonomousPolicyHandler) checkPoliciesTable(c *gin.Context) bool {
	return tableIsThere(c.Request.Context(), h.pool, "autonomous_response_policies")
}

func (h *AutonomousPolicyHandler) checkExecutionsTable(c *gin.Context) bool {
	return tableIsThere(c.Request.Context(), h.pool, "autonomous_response_executions")
}

// ListPolicies returns all autonomous response policies.
// GET /api/v1/admin/autonomous-response/policies
func (h *AutonomousPolicyHandler) ListPolicies(c *gin.Context) {
	if !h.checkPoliciesTable(c) {
		c.JSON(http.StatusOK, gin.H{"policies": []interface{}{}, "total": 0})
		return
	}
	ctx := c.Request.Context()
	rows, err := h.pool.Query(ctx,
		`SELECT id, name, description, trigger_conditions, response_actions,
		        requires_approval, approval_timeout_s, max_scope, is_active,
		        execution_count, success_count, created_at, updated_at
		 FROM autonomous_response_policies ORDER BY created_at DESC`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	defer rows.Close()
	type Policy struct {
		ID                string          `json:"id"`
		Name              string          `json:"name"`
		Description       *string         `json:"description"`
		TriggerConditions json.RawMessage `json:"trigger_conditions"`
		ResponseActions   json.RawMessage `json:"response_actions"`
		RequiresApproval  bool            `json:"requires_approval"`
		ApprovalTimeoutS  int             `json:"approval_timeout_s"`
		MaxScope          string          `json:"max_scope"`
		IsActive          bool            `json:"is_active"`
		ExecutionCount    int             `json:"execution_count"`
		SuccessCount      int             `json:"success_count"`
		CreatedAt         time.Time       `json:"created_at"`
		UpdatedAt         time.Time       `json:"updated_at"`
	}
	var policies []Policy
	for rows.Next() {
		var p Policy
		if err := rows.Scan(&p.ID, &p.Name, &p.Description,
			&p.TriggerConditions, &p.ResponseActions,
			&p.RequiresApproval, &p.ApprovalTimeoutS, &p.MaxScope, &p.IsActive,
			&p.ExecutionCount, &p.SuccessCount,
			&p.CreatedAt, &p.UpdatedAt); err != nil {
			continue
		}
		policies = append(policies, p)
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if policies == nil {
		policies = []Policy{}
	}
	c.JSON(http.StatusOK, gin.H{"policies": policies, "total": len(policies)})
}

// CreatePolicy creates a new autonomous response policy.
// POST /api/v1/admin/autonomous-response/policies
func (h *AutonomousPolicyHandler) CreatePolicy(c *gin.Context) {
	if !h.checkPoliciesTable(c) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "autonomous_response_policies table not ready"})
		return
	}
	var in struct {
		Name              string          `json:"name" binding:"required"`
		Description       *string         `json:"description"`
		TriggerConditions json.RawMessage `json:"trigger_conditions"`
		ResponseActions   json.RawMessage `json:"response_actions"`
		RequiresApproval  bool            `json:"requires_approval"`
		ApprovalTimeoutS  int             `json:"approval_timeout_s"`
		MaxScope          string          `json:"max_scope"`
	}
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if len(in.TriggerConditions) == 0 {
		in.TriggerConditions = json.RawMessage(`[]`)
	}
	if len(in.ResponseActions) == 0 {
		in.ResponseActions = json.RawMessage(`[]`)
	}
	if in.ApprovalTimeoutS <= 0 {
		in.ApprovalTimeoutS = 300
	}
	if in.MaxScope == "" {
		in.MaxScope = "single_host"
	}
	ctx := c.Request.Context()
	var id string
	err := h.pool.QueryRow(ctx,
		`INSERT INTO autonomous_response_policies
		   (name, description, trigger_conditions, response_actions,
		    requires_approval, approval_timeout_s, max_scope)
		 VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id`,
		in.Name, in.Description, in.TriggerConditions, in.ResponseActions,
		in.RequiresApproval, in.ApprovalTimeoutS, in.MaxScope,
	).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id, "message": "policy created"})
}

// UpdatePolicy updates an existing autonomous response policy.
// PUT /api/v1/admin/autonomous-response/policies/:id
func (h *AutonomousPolicyHandler) UpdatePolicy(c *gin.Context) {
	if !h.checkPoliciesTable(c) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "autonomous_response_policies table not ready"})
		return
	}
	id := c.Param("id")
	var in struct {
		Name              *string         `json:"name"`
		Description       *string         `json:"description"`
		TriggerConditions json.RawMessage `json:"trigger_conditions"`
		ResponseActions   json.RawMessage `json:"response_actions"`
		RequiresApproval  *bool           `json:"requires_approval"`
		ApprovalTimeoutS  *int            `json:"approval_timeout_s"`
		MaxScope          *string         `json:"max_scope"`
		IsActive          *bool           `json:"is_active"`
	}
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	ctx := c.Request.Context()
	tag, err := h.pool.Exec(ctx,
		`UPDATE autonomous_response_policies SET
		   name = COALESCE($2, name),
		   description = COALESCE($3, description),
		   trigger_conditions = COALESCE($4::jsonb, trigger_conditions),
		   response_actions = COALESCE($5::jsonb, response_actions),
		   requires_approval = COALESCE($6, requires_approval),
		   approval_timeout_s = COALESCE($7, approval_timeout_s),
		   max_scope = COALESCE($8, max_scope),
		   is_active = COALESCE($9, is_active),
		   updated_at = NOW()
		 WHERE id = $1`,
		id, in.Name, in.Description,
		arNullableJSON(in.TriggerConditions), arNullableJSON(in.ResponseActions),
		in.RequiresApproval, in.ApprovalTimeoutS, in.MaxScope, in.IsActive,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "policy not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "updated"})
}

// DeletePolicy removes an autonomous response policy.
// DELETE /api/v1/admin/autonomous-response/policies/:id
func (h *AutonomousPolicyHandler) DeletePolicy(c *gin.Context) {
	if !h.checkPoliciesTable(c) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "autonomous_response_policies table not ready"})
		return
	}
	id := c.Param("id")
	ctx := c.Request.Context()
	tag, err := h.pool.Exec(ctx, `DELETE FROM autonomous_response_policies WHERE id = $1`, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "policy not found"})
		return
	}
	c.JSON(http.StatusNoContent, nil)
}

// TogglePolicy toggles is_active on an autonomous response policy.
// POST /api/v1/admin/autonomous-response/policies/:id/toggle
func (h *AutonomousPolicyHandler) TogglePolicy(c *gin.Context) {
	if !h.checkPoliciesTable(c) {
		c.JSON(http.StatusNotFound, gin.H{"error": "policy not found"})
		return
	}
	id := c.Param("id")
	ctx := c.Request.Context()
	var isActive bool
	err := h.pool.QueryRow(ctx,
		`UPDATE autonomous_response_policies SET is_active = NOT is_active, updated_at = NOW()
		 WHERE id=$1 RETURNING is_active`, id,
	).Scan(&isActive)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "policy not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": id, "is_active": isActive})
}

// ListExecutions returns autonomous response executions, optionally filtered.
// GET /api/v1/admin/autonomous-response/executions
func (h *AutonomousPolicyHandler) ListExecutions(c *gin.Context) {
	if !h.checkExecutionsTable(c) {
		c.JSON(http.StatusOK, gin.H{"executions": []interface{}{}, "total": 0})
		return
	}
	policyID := c.Query("policy_id")
	status := c.Query("status")
	ctx := c.Request.Context()
	query := `SELECT id, policy_id, trigger_event, status, actions_taken, affected_hosts,
	                 approved_by, approved_at, started_at, completed_at, error_msg, created_at
	          FROM autonomous_response_executions WHERE 1=1`
	args := []interface{}{}
	i := 1
	if policyID != "" {
		query += " AND policy_id = $" + intStr(i)
		args = append(args, policyID)
		i++
	}
	if status != "" {
		query += " AND status = $" + intStr(i)
		args = append(args, status)
		i++
	}
	_ = i
	query += " ORDER BY created_at DESC LIMIT 100"
	rows, err := h.pool.Query(ctx, query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	defer rows.Close()
	type Execution struct {
		ID            string          `json:"id"`
		PolicyID      string          `json:"policy_id"`
		TriggerEvent  json.RawMessage `json:"trigger_event"`
		Status        string          `json:"status"`
		ActionsTaken  json.RawMessage `json:"actions_taken"`
		AffectedHosts json.RawMessage `json:"affected_hosts"`
		ApprovedBy    *string         `json:"approved_by"`
		ApprovedAt    *time.Time      `json:"approved_at"`
		StartedAt     *time.Time      `json:"started_at"`
		CompletedAt   *time.Time      `json:"completed_at"`
		ErrorMsg      *string         `json:"error_msg"`
		CreatedAt     time.Time       `json:"created_at"`
	}
	var execs []Execution
	for rows.Next() {
		var e Execution
		if err := rows.Scan(&e.ID, &e.PolicyID, &e.TriggerEvent, &e.Status,
			&e.ActionsTaken, &e.AffectedHosts,
			&e.ApprovedBy, &e.ApprovedAt,
			&e.StartedAt, &e.CompletedAt, &e.ErrorMsg, &e.CreatedAt); err != nil {
			continue
		}
		execs = append(execs, e)
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if execs == nil {
		execs = []Execution{}
	}
	c.JSON(http.StatusOK, gin.H{"executions": execs, "total": len(execs)})
}

// ApproveExecution approves a pending execution.
// POST /api/v1/admin/autonomous-response/executions/:id/approve
func (h *AutonomousPolicyHandler) ApproveExecution(c *gin.Context) {
	if !h.checkExecutionsTable(c) {
		c.JSON(http.StatusNotFound, gin.H{"error": "execution not found"})
		return
	}
	id := c.Param("id")
	ctx := c.Request.Context()
	approverID, _ := c.Get("user_id")
	approverIDStr, _ := approverID.(string)
	if approverIDStr == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "approver identity required"})
		return
	}
	now := time.Now().UTC()
	tag, err := h.pool.Exec(ctx,
		`UPDATE autonomous_response_executions
		 SET status='approved', approved_by=$2, approved_at=$3
		 WHERE id=$1 AND status='awaiting_approval'`,
		id, approverIDStr, now,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "execution not found or not awaiting approval"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "approved", "approved_by": approverIDStr})
}

// RejectExecution rejects a pending execution.
// POST /api/v1/admin/autonomous-response/executions/:id/reject
func (h *AutonomousPolicyHandler) RejectExecution(c *gin.Context) {
	if !h.checkExecutionsTable(c) {
		c.JSON(http.StatusNotFound, gin.H{"error": "execution not found"})
		return
	}
	id := c.Param("id")
	ctx := c.Request.Context()
	tag, err := h.pool.Exec(ctx,
		`UPDATE autonomous_response_executions SET status='rejected'
		 WHERE id=$1 AND status='awaiting_approval'`, id,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "execution not found or not awaiting approval"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "rejected"})
}

// GetStats returns autonomous response statistics.
// GET /api/v1/admin/autonomous-response/stats
func (h *AutonomousPolicyHandler) GetStats(c *gin.Context) {
	if !h.checkExecutionsTable(c) {
		c.JSON(http.StatusOK, gin.H{
			"executions_by_status": gin.H{},
			"success_rate":         0,
			"avg_response_time_s":  0,
			"total_policies":       0,
			"active_policies":      0,
		})
		return
	}
	ctx := c.Request.Context()
	// Executions by status
	statusRows, err := h.pool.Query(ctx,
		`SELECT status, COUNT(*) FROM autonomous_response_executions GROUP BY status`)
	execsByStatus := map[string]int{}
	total := 0
	completed := 0
	if err == nil {
		defer statusRows.Close()
		for statusRows.Next() {
			var st string
			var cnt int
			if scanErr := statusRows.Scan(&st, &cnt); scanErr == nil {
				execsByStatus[st] = cnt
				total += cnt
				if st == "completed" {
					completed = cnt
				}
			}
		}
		if err := statusRows.Err(); err != nil {
			slog.Warn("row iteration error", "error", err)
		}
	}
	var successRate float64
	if total > 0 {
		successRate = float64(completed) / float64(total) * 100.0
	}
	// Avg response time (seconds between started_at and completed_at)
	var avgResponseTime float64
	if !ReadOK(c, h.pool.QueryRow(ctx,
		`SELECT COALESCE(AVG(EXTRACT(EPOCH FROM (completed_at - started_at))),0)
			 FROM autonomous_response_executions
			 WHERE status='completed' AND started_at IS NOT NULL AND completed_at IS NOT NULL`,
	).Scan(&avgResponseTime)) {
		return
	}
	// Policy counts
	var totalPolicies, activePolicies int
	if h.checkPoliciesTable(c) {
		if !ReadOK(c, h.pool.QueryRow(ctx,
			`SELECT COUNT(*), COALESCE(SUM(CASE WHEN is_active THEN 1 ELSE 0 END), 0)
				 FROM autonomous_response_policies`,
		).Scan(&totalPolicies, &activePolicies)) {
			return
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"executions_by_status": execsByStatus,
		"success_rate":         successRate,
		"avg_response_time_s":  avgResponseTime,
		"total_policies":       totalPolicies,
		"active_policies":      activePolicies,
	})
}

// arNullableJSON returns nil if the input is empty, else the raw JSON bytes.
func arNullableJSON(b json.RawMessage) interface{} {
	if len(b) == 0 {
		return nil
	}
	return b
}

// intStr converts int to string for query building.
func intStr(i int) string {
	return strconv.Itoa(i)
}
