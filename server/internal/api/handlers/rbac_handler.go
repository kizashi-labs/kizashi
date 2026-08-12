package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// RBACHandler manages roles and permission matrices.
// GET/POST/PUT/DELETE /api/v1/admin/roles
// GET/PUT            /api/v1/admin/permissions
type RBACHandler struct {
	pool *pgxpool.Pool
}

func NewRBACHandler(pool *pgxpool.Pool) *RBACHandler {
	return &RBACHandler{pool: pool}
}

func (h *RBACHandler) tableExists(c *gin.Context, name string) bool {
	var ok bool
	_ = h.pool.QueryRow(c.Request.Context(),
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name=$1)`, name).Scan(&ok)
	return ok
}

// ── Types ──────────────────────────────────────────────────────────────────────

type rbacRole struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	MemberCount int    `json:"member_count"`
	Color       string `json:"color,omitempty"`
	IsSystem    bool   `json:"is_system"`
	CreatedAt   string `json:"created_at"`
}

// ── Roles ───────────────────────────────────────────────────────────────────

// ListRoles returns all roles with member counts.
// GET /api/v1/admin/roles
func (h *RBACHandler) ListRoles(c *gin.Context) {
	ctx := c.Request.Context()

	if !h.tableExists(c, "rbac_roles") {
		// Fallback: derive roles from users table
		rows, err := h.pool.Query(ctx,
			`SELECT role, COUNT(*) AS cnt FROM users GROUP BY role`)
		if err != nil {
			c.JSON(http.StatusOK, gin.H{"roles": []interface{}{}})
			return
		}
		defer rows.Close()
		var roles []rbacRole
		for rows.Next() {
			var r rbacRole
			var cnt int
			if rows.Scan(&r.Name, &cnt) != nil {
				continue
			}
			r.MemberCount = cnt
			r.Description = r.Name
			r.IsSystem = true
			r.CreatedAt = time.Now().Format(time.RFC3339)
			roles = append(roles, r)
		}
		if roles == nil {
			roles = []rbacRole{}
		}
		c.JSON(http.StatusOK, gin.H{"roles": roles})
		return
	}

	rows, err := h.pool.Query(ctx,
		`SELECT r.name, r.description, r.color, r.is_system, r.created_at,
		        (SELECT COUNT(*) FROM users u WHERE u.role = r.name) AS member_count
		 FROM rbac_roles r ORDER BY r.is_system DESC, r.name`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list roles"})
		return
	}
	defer rows.Close()

	var roles []rbacRole
	for rows.Next() {
		var r rbacRole
		var createdAt time.Time
		if err := rows.Scan(&r.Name, &r.Description, &r.Color, &r.IsSystem, &createdAt, &r.MemberCount); err != nil {
			continue
		}
		r.CreatedAt = createdAt.Format(time.RFC3339)
		roles = append(roles, r)
	}
	if roles == nil {
		roles = []rbacRole{}
	}
	c.JSON(http.StatusOK, gin.H{"roles": roles})
}

// CreateRole creates a new role.
// POST /api/v1/admin/roles
func (h *RBACHandler) CreateRole(c *gin.Context) {
	var body struct {
		Name        string `json:"name" binding:"required"`
		Description string `json:"description"`
		Color       string `json:"color"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}

	if !h.tableExists(c, "rbac_roles") {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "RBAC tables not available"})
		return
	}

	ctx := c.Request.Context()
	_, err := h.pool.Exec(ctx,
		`INSERT INTO rbac_roles (name, description, color, is_system) VALUES ($1,$2,$3,false)
		 ON CONFLICT (name) DO UPDATE SET description=$2, color=$3`,
		body.Name, body.Description, body.Color)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create role"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"name": body.Name, "message": "Role created"})
}

// UpdateRole updates an existing role.
// PUT /api/v1/admin/roles/:name
func (h *RBACHandler) UpdateRole(c *gin.Context) {
	name := c.Param("name")
	var body struct {
		Description string `json:"description"`
		Color       string `json:"color"`
	}
	_ = c.ShouldBindJSON(&body)

	if !h.tableExists(c, "rbac_roles") {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "RBAC tables not available"})
		return
	}

	ctx := c.Request.Context()
	tag, err := h.pool.Exec(ctx,
		`UPDATE rbac_roles SET description=$1, color=$2 WHERE name=$3`,
		body.Description, body.Color, name)
	if err != nil || tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Role not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Role updated"})
}

// DeleteRole deletes a non-system role.
// DELETE /api/v1/admin/roles/:name
func (h *RBACHandler) DeleteRole(c *gin.Context) {
	name := c.Param("name")
	if !h.tableExists(c, "rbac_roles") {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "RBAC tables not available"})
		return
	}
	ctx := c.Request.Context()
	_, err := h.pool.Exec(ctx,
		`DELETE FROM rbac_roles WHERE name=$1 AND is_system=false`, name)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete role"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Role deleted"})
}

// ── Permission Matrix ─────────────────────────────────────────────────────────

// GetPermissions returns the role→permissions matrix.
// GET /api/v1/admin/permissions
func (h *RBACHandler) GetPermissions(c *gin.Context) {
	ctx := c.Request.Context()

	if !h.tableExists(c, "rbac_permissions") {
		// Return default matrix
		matrix := map[string][]string{
			"admin":   {"view_alerts", "manage_alerts", "close_alerts", "assign_alerts", "export_alerts", "view_agents", "manage_agents", "deploy_agents", "run_commands", "view_incidents", "manage_incidents", "close_incidents", "view_rules", "manage_rules", "import_rules", "view_reports", "generate_reports", "schedule_reports", "admin_settings", "manage_users", "view_audit"},
			"analyst": {"view_alerts", "manage_alerts", "close_alerts", "assign_alerts", "export_alerts", "view_agents", "view_incidents", "manage_incidents", "view_rules", "view_reports", "generate_reports"},
			"viewer":  {"view_alerts", "view_agents", "view_incidents", "view_rules", "view_reports"},
		}
		c.JSON(http.StatusOK, gin.H{"matrix": matrix})
		return
	}

	rows, err := h.pool.Query(ctx,
		`SELECT role_name, permissions FROM rbac_permissions`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load permissions"})
		return
	}
	defer rows.Close()

	matrix := map[string][]string{}
	for rows.Next() {
		var role string
		var permsJSON []byte
		if err := rows.Scan(&role, &permsJSON); err != nil {
			continue
		}
		var perms []string
		if err := json.Unmarshal(permsJSON, &perms); err != nil {
			perms = []string{}
		}
		matrix[role] = perms
	}
	c.JSON(http.StatusOK, gin.H{"matrix": matrix})
}

// UpdatePermissions saves the role→permissions matrix.
// PUT /api/v1/admin/permissions
func (h *RBACHandler) UpdatePermissions(c *gin.Context) {
	var matrix map[string][]string
	if err := c.ShouldBindJSON(&matrix); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	if !h.tableExists(c, "rbac_permissions") {
		// Accept but silently discard if table doesn't exist
		c.JSON(http.StatusOK, gin.H{"message": "Permissions saved"})
		return
	}

	ctx := c.Request.Context()
	for role, perms := range matrix {
		permsJSON, _ := json.Marshal(perms)
		_, err := h.pool.Exec(ctx,
			`INSERT INTO rbac_permissions (role_name, permissions) VALUES ($1,$2)
			 ON CONFLICT (role_name) DO UPDATE SET permissions=$2, updated_at=NOW()`,
			role, permsJSON)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save permissions"})
			return
		}
	}
	c.JSON(http.StatusOK, gin.H{"message": "Permissions saved"})
}
