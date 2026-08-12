package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// EDRPolicyHandler provides CRUD endpoints for EDR policies.
type EDRPolicyHandler struct {
	pool *pgxpool.Pool
}

// NewEDRPolicyHandler creates an EDRPolicyHandler.
func NewEDRPolicyHandler(pool *pgxpool.Pool) *EDRPolicyHandler {
	return &EDRPolicyHandler{pool: pool}
}

func (h *EDRPolicyHandler) tableExists(c *gin.Context, name string) bool {
	var exists bool
	_ = h.pool.QueryRow(c.Request.Context(),
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name=$1)`,
		name,
	).Scan(&exists)
	return exists
}

type edrPolicy struct {
	ID             string          `json:"id"`
	Name           string          `json:"name"`
	Description    string          `json:"description"`
	PolicyType     string          `json:"policy_type"`
	Rules          json.RawMessage `json:"rules"`
	Enabled        bool            `json:"enabled"`
	AssignedGroups json.RawMessage `json:"assigned_groups"`
	CreatedBy      *string         `json:"created_by,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
	UpdatedAt      time.Time       `json:"updated_at"`
	// computed
	AssignmentCount int `json:"assignment_count,omitempty"`
}

type edrPolicyAssignment struct {
	ID         string    `json:"id"`
	PolicyID   string    `json:"policy_id"`
	AgentID    *string   `json:"agent_id,omitempty"`
	GroupID    *string   `json:"group_id,omitempty"`
	AssignedAt time.Time `json:"assigned_at"`
	AssignedBy *string   `json:"assigned_by,omitempty"`
}

// List handles GET /admin/edr-policies
func (h *EDRPolicyHandler) List(c *gin.Context) {
	if !h.tableExists(c, "edr_policies") {
		c.JSON(http.StatusOK, gin.H{"policies": []interface{}{}, "count": 0})
		return
	}
	rows, err := h.pool.Query(c.Request.Context(), `
		SELECT p.id, p.name, COALESCE(p.description,''), p.policy_type,
		       p.rules, p.enabled, p.assigned_groups,
		       p.created_by::text, p.created_at, p.updated_at,
		       COUNT(a.id) AS assignment_count
		FROM edr_policies p
		LEFT JOIN edr_policy_assignments a ON a.policy_id = p.id
		GROUP BY p.id
		ORDER BY p.created_at DESC`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ポリシーの取得に失敗しました"})
		return
	}
	defer rows.Close()

	var policies []edrPolicy
	for rows.Next() {
		p := edrPolicy{}
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.PolicyType,
			&p.Rules, &p.Enabled, &p.AssignedGroups,
			&p.CreatedBy, &p.CreatedAt, &p.UpdatedAt, &p.AssignmentCount); err != nil {
			continue
		}
		policies = append(policies, p)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}
	if policies == nil {
		policies = []edrPolicy{}
	}
	c.JSON(http.StatusOK, gin.H{"policies": policies, "count": len(policies)})
}

// Get handles GET /admin/edr-policies/:id
func (h *EDRPolicyHandler) Get(c *gin.Context) {
	id := c.Param("id")
	if !h.tableExists(c, "edr_policies") {
		c.JSON(http.StatusNotFound, gin.H{"error": "ポリシーが見つかりません"})
		return
	}
	p := edrPolicy{}
	err := h.pool.QueryRow(c.Request.Context(), `
		SELECT p.id, p.name, COALESCE(p.description,''), p.policy_type,
		       p.rules, p.enabled, p.assigned_groups,
		       p.created_by::text, p.created_at, p.updated_at,
		       (SELECT COUNT(*) FROM edr_policy_assignments WHERE policy_id=p.id) AS cnt
		FROM edr_policies p WHERE p.id = $1`, id,
	).Scan(&p.ID, &p.Name, &p.Description, &p.PolicyType,
		&p.Rules, &p.Enabled, &p.AssignedGroups,
		&p.CreatedBy, &p.CreatedAt, &p.UpdatedAt, &p.AssignmentCount)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "ポリシーが見つかりません"})
		return
	}

	// Include assignments
	assignments := h.getAssignments(c, id)
	c.JSON(http.StatusOK, gin.H{"policy": p, "assignments": assignments})
}

// Create handles POST /admin/edr-policies
func (h *EDRPolicyHandler) Create(c *gin.Context) {
	if !h.tableExists(c, "edr_policies") {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "テーブルが存在しません"})
		return
	}
	var req struct {
		Name        string          `json:"name"        binding:"required"`
		Description string          `json:"description"`
		PolicyType  string          `json:"policy_type"`
		Rules       json.RawMessage `json:"rules"`
		Enabled     *bool           `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "リクエストが無効です"})
		return
	}
	if req.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "名前は必須です"})
		return
	}
	if req.PolicyType == "" {
		req.PolicyType = "standard"
	}
	if len(req.Rules) == 0 {
		req.Rules = json.RawMessage("{}")
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	var createdByArg interface{}
	if uid, ok := c.Get("user_id"); ok {
		if s, ok := uid.(string); ok && s != "" {
			createdByArg = s
		}
	}

	var id string
	err := h.pool.QueryRow(c.Request.Context(), `
		INSERT INTO edr_policies (name, description, policy_type, rules, enabled, created_by)
		VALUES ($1, $2, $3, $4, $5, $6::uuid)
		RETURNING id`,
		req.Name, req.Description, req.PolicyType, req.Rules, enabled, createdByArg,
	).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ポリシーの作成に失敗しました"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id, "message": "作成しました"})
}

// Update handles PUT /admin/edr-policies/:id
func (h *EDRPolicyHandler) Update(c *gin.Context) {
	id := c.Param("id")
	if !h.tableExists(c, "edr_policies") {
		c.JSON(http.StatusNotFound, gin.H{"error": "ポリシーが見つかりません"})
		return
	}
	var req struct {
		Name        string          `json:"name"`
		Description string          `json:"description"`
		PolicyType  string          `json:"policy_type"`
		Rules       json.RawMessage `json:"rules"`
		Enabled     *bool           `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "リクエストが無効です"})
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	if len(req.Rules) == 0 {
		req.Rules = json.RawMessage("{}")
	}
	_, err := h.pool.Exec(c.Request.Context(), `
		UPDATE edr_policies SET name=$2, description=$3, policy_type=$4,
		       rules=$5, enabled=$6, updated_at=NOW()
		WHERE id=$1`,
		id, req.Name, req.Description, req.PolicyType, req.Rules, enabled,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ポリシーの更新に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "更新しました"})
}

// Delete handles DELETE /admin/edr-policies/:id
func (h *EDRPolicyHandler) Delete(c *gin.Context) {
	id := c.Param("id")
	if !h.tableExists(c, "edr_policies") {
		c.JSON(http.StatusOK, gin.H{"message": "削除しました"})
		return
	}
	_, err := h.pool.Exec(c.Request.Context(), "DELETE FROM edr_policies WHERE id = $1", id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ポリシーの削除に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "削除しました"})
}

// Toggle handles POST /admin/edr-policies/:id/toggle
func (h *EDRPolicyHandler) Toggle(c *gin.Context) {
	id := c.Param("id")
	if !h.tableExists(c, "edr_policies") {
		c.JSON(http.StatusNotFound, gin.H{"error": "ポリシーが見つかりません"})
		return
	}
	var enabled bool
	err := h.pool.QueryRow(c.Request.Context(), `
		UPDATE edr_policies SET enabled = NOT enabled, updated_at=NOW() WHERE id=$1 RETURNING enabled`, id,
	).Scan(&enabled)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "切り替えに失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": id, "enabled": enabled})
}

// AssignToGroup handles POST /admin/edr-policies/:id/assign
func (h *EDRPolicyHandler) AssignToGroup(c *gin.Context) {
	policyID := c.Param("id")
	if !h.tableExists(c, "edr_policy_assignments") {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "テーブルが存在しません"})
		return
	}
	var req struct {
		GroupID string `json:"group_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.GroupID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "group_idは必須です"})
		return
	}

	var assignedByArg interface{}
	if uid, ok := c.Get("user_id"); ok {
		if s, ok := uid.(string); ok && s != "" {
			assignedByArg = s
		}
	}

	var id string
	err := h.pool.QueryRow(c.Request.Context(), `
		INSERT INTO edr_policy_assignments (policy_id, group_id, assigned_by)
		VALUES ($1, $2::uuid, $3::uuid)
		ON CONFLICT (policy_id, group_id) DO UPDATE SET assigned_at=NOW()
		RETURNING id`,
		policyID, req.GroupID, assignedByArg,
	).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "グループへの割り当てに失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": id, "policy_id": policyID, "group_id": req.GroupID})
}

// AssignToAgent handles POST /admin/edr-policies/:id/assign-agent
func (h *EDRPolicyHandler) AssignToAgent(c *gin.Context) {
	policyID := c.Param("id")
	if !h.tableExists(c, "edr_policy_assignments") {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "テーブルが存在しません"})
		return
	}
	var req struct {
		AgentID string `json:"agent_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.AgentID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "agent_idは必須です"})
		return
	}

	var assignedByArg interface{}
	if uid, ok := c.Get("user_id"); ok {
		if s, ok := uid.(string); ok && s != "" {
			assignedByArg = s
		}
	}

	var id string
	err := h.pool.QueryRow(c.Request.Context(), `
		INSERT INTO edr_policy_assignments (policy_id, agent_id, assigned_by)
		VALUES ($1, $2::uuid, $3::uuid)
		ON CONFLICT (policy_id, agent_id) DO UPDATE SET assigned_at=NOW()
		RETURNING id`,
		policyID, req.AgentID, assignedByArg,
	).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "エージェントへの割り当てに失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": id, "policy_id": policyID, "agent_id": req.AgentID})
}

// GetAssignments handles GET /admin/edr-policies/:id/assignments
func (h *EDRPolicyHandler) GetAssignments(c *gin.Context) {
	id := c.Param("id")
	assignments := h.getAssignments(c, id)
	c.JSON(http.StatusOK, gin.H{"assignments": assignments, "count": len(assignments)})
}

func (h *EDRPolicyHandler) getAssignments(c *gin.Context, policyID string) []edrPolicyAssignment {
	if !h.tableExists(c, "edr_policy_assignments") {
		return []edrPolicyAssignment{}
	}
	rows, err := h.pool.Query(c.Request.Context(), `
		SELECT id, policy_id, agent_id::text, group_id::text, assigned_at, assigned_by::text
		FROM edr_policy_assignments WHERE policy_id = $1
		ORDER BY assigned_at DESC`, policyID)
	if err != nil {
		return []edrPolicyAssignment{}
	}
	defer rows.Close()

	var assignments []edrPolicyAssignment
	for rows.Next() {
		a := edrPolicyAssignment{}
		if err := rows.Scan(&a.ID, &a.PolicyID, &a.AgentID, &a.GroupID, &a.AssignedAt, &a.AssignedBy); err != nil {
			continue
		}
		assignments = append(assignments, a)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}
	if assignments == nil {
		assignments = []edrPolicyAssignment{}
	}
	return assignments
}
