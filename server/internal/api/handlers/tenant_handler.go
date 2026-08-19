package handlers

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

type TenantHandler struct {
	pool *pgxpool.Pool
}

func NewTenantHandler(pool *pgxpool.Pool) *TenantHandler {
	return &TenantHandler{pool: pool}
}

type Tenant struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Slug       string    `json:"slug"`
	Plan       string    `json:"plan"`
	MaxAgents  int       `json:"max_agents"`
	IsActive   bool      `json:"is_active"`
	AgentCount int       `json:"agent_count,omitempty"`
	UserCount  int       `json:"user_count,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

// GET /api/v1/tenants  (super-admin only)
func (h *TenantHandler) List(c *gin.Context) {
	rows, err := h.pool.Query(c.Request.Context(),
		`SELECT t.id, t.name, t.slug, t.plan, t.max_agents, t.is_active, t.created_at,
		        COUNT(DISTINCT a.id) as agent_count,
		        COUNT(DISTINCT u.id) as user_count
		 FROM tenants t
		 LEFT JOIN agents a ON a.tenant_id = t.id
		 LEFT JOIN users  u ON u.tenant_id = t.id
		 GROUP BY t.id ORDER BY t.created_at`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "query failed"})
		return
	}
	defer rows.Close()
	var tenants []Tenant
	for rows.Next() {
		var t Tenant
		if err := rows.Scan(&t.ID, &t.Name, &t.Slug, &t.Plan, &t.MaxAgents, &t.IsActive, &t.CreatedAt,
			&t.AgentCount, &t.UserCount); err != nil {
			slog.Warn("tenant: list scan error", "error", err)
			continue
		}
		tenants = append(tenants, t)
	}
	if err := rows.Err(); err != nil {
		slog.Error("rows.Err: 結果の読み出しが途中で失敗しました", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "query failed"})
		return
	}
	if tenants == nil {
		tenants = []Tenant{}
	}
	c.JSON(http.StatusOK, tenants)
}

// POST /api/v1/tenants  (super-admin only)
func (h *TenantHandler) Create(c *gin.Context) {
	var req struct {
		Name      string `json:"name" binding:"required"`
		Slug      string `json:"slug" binding:"required"`
		Plan      string `json:"plan"`
		MaxAgents int    `json:"max_agents"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Plan == "" {
		req.Plan = "standard"
	}
	if req.MaxAgents == 0 {
		req.MaxAgents = 100
	}
	var id string
	err := h.pool.QueryRow(c.Request.Context(),
		`INSERT INTO tenants (name, slug, plan, max_agents) VALUES ($1,$2,$3,$4) RETURNING id`,
		req.Name, req.Slug, req.Plan, req.MaxAgents,
	).Scan(&id)
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "tenant already exists or invalid data"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id})
}

// GET /api/v1/tenants/:id
func (h *TenantHandler) Get(c *gin.Context) {
	id := c.Param("id")
	var t Tenant
	err := h.pool.QueryRow(c.Request.Context(),
		`SELECT id, name, slug, plan, max_agents, is_active, created_at FROM tenants WHERE id=$1`, id,
	).Scan(&t.ID, &t.Name, &t.Slug, &t.Plan, &t.MaxAgents, &t.IsActive, &t.CreatedAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "tenant not found"})
		return
	}
	c.JSON(http.StatusOK, t)
}

// PATCH /api/v1/tenants/:id
func (h *TenantHandler) Update(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Plan      *string `json:"plan"`
		MaxAgents *int    `json:"max_agents"`
		IsActive  *bool   `json:"is_active"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	ctx := c.Request.Context()
	if req.Plan != nil {
		if _, err := h.pool.Exec(ctx, `UPDATE tenants SET plan=$1 WHERE id=$2`, req.Plan, id); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "plan update failed"})
			return
		}
	}
	if req.MaxAgents != nil {
		if _, err := h.pool.Exec(ctx, `UPDATE tenants SET max_agents=$1 WHERE id=$2`, req.MaxAgents, id); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "max_agents update failed"})
			return
		}
	}
	if req.IsActive != nil {
		if _, err := h.pool.Exec(ctx, `UPDATE tenants SET is_active=$1 WHERE id=$2`, req.IsActive, id); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "is_active update failed"})
			return
		}
	}
	c.JSON(http.StatusOK, gin.H{"status": "updated"})
}

// DELETE /api/v1/tenants/:id
func (h *TenantHandler) Delete(c *gin.Context) {
	id := c.Param("id")
	if id == "00000000-0000-0000-0000-000000000001" {
		c.JSON(http.StatusForbidden, gin.H{"error": "cannot delete default tenant"})
		return
	}
	_, err := h.pool.Exec(c.Request.Context(), `DELETE FROM tenants WHERE id=$1`, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "delete failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}
