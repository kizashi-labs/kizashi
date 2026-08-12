package handlers

import (
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/edr-platform/server/internal/api/response"
)

// MultiTenantHandler handles enhanced multi-tenant management endpoints.
type MultiTenantHandler struct {
	pool *pgxpool.Pool
}

// NewMultiTenantHandler creates a new MultiTenantHandler.
func NewMultiTenantHandler(pool *pgxpool.Pool) *MultiTenantHandler {
	return &MultiTenantHandler{pool: pool}
}

type tenantWithQuota struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Slug            string    `json:"slug"`
	Plan            string    `json:"plan"`
	IsActive        bool      `json:"is_active"`
	CreatedAt       time.Time `json:"created_at"`
	MaxAgents       *int      `json:"max_agents,omitempty"`
	MaxUsers        *int      `json:"max_users,omitempty"`
	MaxStorageGB    *int64    `json:"max_storage_gb,omitempty"`
	MaxAlertsPerDay *int      `json:"max_alerts_per_day,omitempty"`
	QuotaPlan       *string   `json:"quota_plan,omitempty"`
	AgentCount      int       `json:"agent_count"`
	UserCount       int       `json:"user_count"`
	StorageUsedGB   float64   `json:"storage_used_gb"`
}

type tenantAuditEntry struct {
	ID         string    `json:"id"`
	TenantID   string    `json:"tenant_id"`
	ActorID    *string   `json:"actor_id,omitempty"`
	ActorEmail *string   `json:"actor_email,omitempty"`
	Action     string    `json:"action"`
	Resource   *string   `json:"resource,omitempty"`
	ResourceID *string   `json:"resource_id,omitempty"`
	IPAddress  *string   `json:"ip_address,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

// ListTenants handles GET /api/v1/admin/tenants
func (h *MultiTenantHandler) ListTenants(c *gin.Context) {
	rows, err := h.pool.Query(c.Request.Context(), `
		SELECT t.id, t.name, t.slug, t.plan, t.is_active, t.created_at,
		       q.max_agents, q.max_users, q.max_storage_gb, q.max_alerts_per_day, q.plan AS quota_plan,
		       COUNT(DISTINCT a.id) AS agent_count,
		       COUNT(DISTINCT u.id) AS user_count,
		       COALESCE((
		           (SELECT COUNT(*) FROM alerts          WHERE tenant_id = t.id) * 2048 +
		           (SELECT COUNT(*) FROM incidents       WHERE tenant_id = t.id) * 3072 +
		           (SELECT COUNT(*) FROM rules           WHERE tenant_id = t.id) * 1024 +
		           (SELECT COUNT(*) FROM tenant_audit_log WHERE tenant_id = t.id) * 512
		       ) / 1073741824.0, 0) AS storage_used_gb
		FROM tenants t
		LEFT JOIN tenant_quotas q ON q.tenant_id = t.id
		LEFT JOIN agents a ON a.tenant_id = t.id
		LEFT JOIN users  u ON u.tenant_id = t.id
		GROUP BY t.id, q.max_agents, q.max_users, q.max_storage_gb, q.max_alerts_per_day, q.plan
		ORDER BY t.created_at DESC
	`)
	if err != nil {
		response.InternalError(c, "failed to list tenants")
		return
	}
	defer rows.Close()

	var tenants []tenantWithQuota
	for rows.Next() {
		var t tenantWithQuota
		if err := rows.Scan(
			&t.ID, &t.Name, &t.Slug, &t.Plan, &t.IsActive, &t.CreatedAt,
			&t.MaxAgents, &t.MaxUsers, &t.MaxStorageGB, &t.MaxAlertsPerDay, &t.QuotaPlan,
			&t.AgentCount, &t.UserCount, &t.StorageUsedGB,
		); err != nil {
			continue
		}
		tenants = append(tenants, t)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}
	if tenants == nil {
		tenants = []tenantWithQuota{}
	}
	response.OK(c, tenants)
}

// GetTenant handles GET /api/v1/admin/tenants/:id
func (h *MultiTenantHandler) GetTenant(c *gin.Context) {
	id := c.Param("id")
	var t tenantWithQuota
	err := h.pool.QueryRow(c.Request.Context(), `
		SELECT t.id, t.name, t.slug, t.plan, t.is_active, t.created_at,
		       q.max_agents, q.max_users, q.max_storage_gb, q.max_alerts_per_day, q.plan AS quota_plan
		FROM tenants t
		LEFT JOIN tenant_quotas q ON q.tenant_id = t.id
		WHERE t.id = $1
	`, id).Scan(
		&t.ID, &t.Name, &t.Slug, &t.Plan, &t.IsActive, &t.CreatedAt,
		&t.MaxAgents, &t.MaxUsers, &t.MaxStorageGB, &t.MaxAlertsPerDay, &t.QuotaPlan,
	)
	if err != nil {
		response.NotFound(c, "tenant not found")
		return
	}
	response.OK(c, t)
}

// CreateTenant handles POST /api/v1/admin/tenants
func (h *MultiTenantHandler) CreateTenant(c *gin.Context) {
	var req struct {
		Name      string `json:"name" binding:"required"`
		Slug      string `json:"slug" binding:"required"`
		Plan      string `json:"plan"`
		MaxAgents int    `json:"max_agents"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "invalid request: "+err.Error())
		return
	}
	if req.Plan == "" {
		req.Plan = "standard"
	}
	if req.MaxAgents == 0 {
		req.MaxAgents = 100
	}

	tenantID := uuid.New().String()
	ctx := c.Request.Context()

	tx, err := h.pool.Begin(ctx)
	if err != nil {
		response.InternalError(c, "failed to begin transaction")
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var createdAt time.Time
	err = tx.QueryRow(ctx, `
		INSERT INTO tenants (id, name, slug, plan, max_agents, is_active)
		VALUES ($1, $2, $3, $4, $5, true)
		RETURNING created_at
	`, tenantID, req.Name, req.Slug, req.Plan, req.MaxAgents).Scan(&createdAt)
	if err != nil {
		response.InternalError(c, "failed to create tenant: "+err.Error())
		return
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO tenant_quotas (tenant_id, max_agents, plan)
		VALUES ($1, $2, $3)
	`, tenantID, req.MaxAgents, req.Plan)
	if err != nil {
		response.InternalError(c, "failed to initialize tenant quota: "+err.Error())
		return
	}

	if err := tx.Commit(ctx); err != nil {
		response.InternalError(c, "failed to commit transaction")
		return
	}

	response.Created(c, gin.H{
		"id":         tenantID,
		"name":       req.Name,
		"slug":       req.Slug,
		"plan":       req.Plan,
		"max_agents": req.MaxAgents,
		"is_active":  true,
		"created_at": createdAt,
	})
}

// UpdateTenant handles PUT /api/v1/admin/tenants/:id
func (h *MultiTenantHandler) UpdateTenant(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Name      *string `json:"name"`
		Slug      *string `json:"slug"`
		Plan      *string `json:"plan"`
		MaxAgents *int    `json:"max_agents"`
		IsActive  *bool   `json:"is_active"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "invalid request: "+err.Error())
		return
	}

	res, err := h.pool.Exec(c.Request.Context(), `
		UPDATE tenants SET
		  name       = COALESCE($2, name),
		  slug       = COALESCE($3, slug),
		  plan       = COALESCE($4, plan),
		  max_agents = COALESCE($5, max_agents),
		  is_active  = COALESCE($6, is_active)
		WHERE id = $1
	`, id, req.Name, req.Slug, req.Plan, req.MaxAgents, req.IsActive)
	if err != nil {
		response.InternalError(c, "failed to update tenant")
		return
	}
	if res.RowsAffected() == 0 {
		response.NotFound(c, "tenant not found")
		return
	}
	response.OK(c, gin.H{"message": "tenant updated"})
}

// DeleteTenant handles DELETE /api/v1/admin/tenants/:id
func (h *MultiTenantHandler) DeleteTenant(c *gin.Context) {
	id := c.Param("id")
	res, err := h.pool.Exec(c.Request.Context(), `DELETE FROM tenants WHERE id = $1`, id)
	if err != nil {
		response.InternalError(c, "failed to delete tenant")
		return
	}
	if res.RowsAffected() == 0 {
		response.NotFound(c, "tenant not found")
		return
	}
	response.NoContent(c)
}

// UpdateQuota handles PUT /api/v1/admin/tenants/:id/quota
func (h *MultiTenantHandler) UpdateQuota(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		MaxAgents       *int    `json:"max_agents"`
		MaxUsers        *int    `json:"max_users"`
		MaxStorageGB    *int64  `json:"max_storage_gb"`
		MaxAlertsPerDay *int    `json:"max_alerts_per_day"`
		Plan            *string `json:"plan"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "invalid request: "+err.Error())
		return
	}

	res, err := h.pool.Exec(c.Request.Context(), `
		INSERT INTO tenant_quotas (tenant_id, max_agents, max_users, max_storage_gb, max_alerts_per_day, plan, updated_at)
		VALUES ($1,
		  COALESCE($2, 100),
		  COALESCE($3, 50),
		  COALESCE($4, 100),
		  COALESCE($5, 10000),
		  COALESCE($6, 'standard'),
		  NOW()
		)
		ON CONFLICT (tenant_id) DO UPDATE SET
		  max_agents        = COALESCE($2, tenant_quotas.max_agents),
		  max_users         = COALESCE($3, tenant_quotas.max_users),
		  max_storage_gb    = COALESCE($4, tenant_quotas.max_storage_gb),
		  max_alerts_per_day = COALESCE($5, tenant_quotas.max_alerts_per_day),
		  plan              = COALESCE($6, tenant_quotas.plan),
		  updated_at        = NOW()
	`, id, req.MaxAgents, req.MaxUsers, req.MaxStorageGB, req.MaxAlertsPerDay, req.Plan)
	if err != nil {
		response.InternalError(c, "failed to update quota: "+err.Error())
		return
	}
	if res.RowsAffected() == 0 {
		response.NotFound(c, "tenant not found")
		return
	}
	response.OK(c, gin.H{"message": "quota updated"})
}

// GetTenantAuditLog handles GET /api/v1/admin/tenants/:id/audit
func (h *MultiTenantHandler) GetTenantAuditLog(c *gin.Context) {
	id := c.Param("id")
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	var total int
	_ = h.pool.QueryRow(c.Request.Context(),
		`SELECT COUNT(*) FROM tenant_audit_log WHERE tenant_id = $1`, id,
	).Scan(&total)

	rows, err := h.pool.Query(c.Request.Context(), `
		SELECT id, tenant_id, actor_id::text, actor_email, action, resource, resource_id,
		       host(ip_address), created_at
		FROM tenant_audit_log
		WHERE tenant_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`, id, limit, offset)
	if err != nil {
		response.InternalError(c, "failed to query audit log")
		return
	}
	defer rows.Close()

	var entries []tenantAuditEntry
	for rows.Next() {
		var e tenantAuditEntry
		if err := rows.Scan(
			&e.ID, &e.TenantID, &e.ActorID, &e.ActorEmail,
			&e.Action, &e.Resource, &e.ResourceID, &e.IPAddress, &e.CreatedAt,
		); err != nil {
			continue
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}
	if entries == nil {
		entries = []tenantAuditEntry{}
	}
	response.Paginated(c, entries, total, limit, offset)
}

// GetTenantStats handles GET /api/v1/admin/tenants/:id/stats
func (h *MultiTenantHandler) GetTenantStats(c *gin.Context) {
	id := c.Param("id")
	ctx := c.Request.Context()

	var agentCount, userCount, alertCount int
	_ = h.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM agents WHERE tenant_id = $1`, id,
	).Scan(&agentCount)
	_ = h.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM users WHERE tenant_id = $1`, id,
	).Scan(&userCount)
	_ = h.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM alerts WHERE tenant_id = $1 AND created_at >= NOW() - INTERVAL '24 hours'`, id,
	).Scan(&alertCount)

	response.OK(c, gin.H{
		"tenant_id":       id,
		"agent_count":     agentCount,
		"user_count":      userCount,
		"alerts_last_24h": alertCount,
	})
}

// Ensure http import is used
var _ = http.StatusOK
