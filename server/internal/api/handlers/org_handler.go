package handlers

import (
	"net/http"

	"github.com/edr-platform/server/internal/tenant"
	"github.com/gin-gonic/gin"
)

// OrgHandler handles organization management endpoints.
type OrgHandler struct {
	store *tenant.Store
}

// NewOrgHandler creates a new OrgHandler.
func NewOrgHandler(store *tenant.Store) *OrgHandler {
	return &OrgHandler{store: store}
}

// ListOrgs handles GET /api/v1/admin/organizations (super-admin only).
func (h *OrgHandler) ListOrgs(c *gin.Context) {
	orgs, err := h.store.List(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list organizations"})
		return
	}
	c.JSON(http.StatusOK, orgs)
}

// CreateOrg handles POST /api/v1/admin/organizations.
func (h *OrgHandler) CreateOrg(c *gin.Context) {
	var org tenant.Organization
	if err := c.ShouldBindJSON(&org); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if org.Plan == "" {
		org.Plan = "free"
	}
	if org.AgentLimit == 0 {
		org.AgentLimit = 10
	}
	if org.UserLimit == 0 {
		org.UserLimit = 5
	}
	org.Enabled = true

	created, err := h.store.Create(c.Request.Context(), &org)
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "organization already exists or invalid data"})
		return
	}
	c.JSON(http.StatusCreated, created)
}

// GetOrg handles GET /api/v1/admin/organizations/:id — returns org details + stats.
func (h *OrgHandler) GetOrg(c *gin.Context) {
	id := c.Param("id")
	org, err := h.store.Get(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "organization not found"})
		return
	}
	stats, _ := h.store.GetStats(c.Request.Context(), id)
	c.JSON(http.StatusOK, gin.H{"organization": org, "stats": stats})
}

// UpdateOrg handles PUT /api/v1/admin/organizations/:id.
func (h *OrgHandler) UpdateOrg(c *gin.Context) {
	id := c.Param("id")
	var org tenant.Organization
	if err := c.ShouldBindJSON(&org); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	updated, err := h.store.Update(c.Request.Context(), id, &org)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update organization"})
		return
	}
	c.JSON(http.StatusOK, updated)
}

// DeleteOrg handles DELETE /api/v1/admin/organizations/:id.
func (h *OrgHandler) DeleteOrg(c *gin.Context) {
	id := c.Param("id")
	if id == "00000000-0000-0000-0000-000000000001" {
		c.JSON(http.StatusForbidden, gin.H{"error": "cannot delete default organization"})
		return
	}
	if err := h.store.Delete(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete organization"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}

// GetCurrentOrg handles GET /api/v1/org/current.
func (h *OrgHandler) GetCurrentOrg(c *gin.Context) {
	orgID, _ := c.Get("org_id")
	orgIDStr, _ := orgID.(string)
	if orgIDStr == "" {
		// Fall back to tenant_id from JWT
		if tid, exists := c.Get("tenant_id"); exists {
			orgIDStr, _ = tid.(string)
		}
	}
	if orgIDStr == "" {
		c.JSON(http.StatusOK, gin.H{"organization": nil})
		return
	}
	org, err := h.store.Get(c.Request.Context(), orgIDStr)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "organization not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"organization": org})
}

// UpdateOrgSettings handles PUT /api/v1/org/settings.
func (h *OrgHandler) UpdateOrgSettings(c *gin.Context) {
	orgID, _ := c.Get("org_id")
	orgIDStr, _ := orgID.(string)
	if orgIDStr == "" {
		if tid, exists := c.Get("tenant_id"); exists {
			orgIDStr, _ = tid.(string)
		}
	}
	if orgIDStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no organization context"})
		return
	}

	org, err := h.store.Get(c.Request.Context(), orgIDStr)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "organization not found"})
		return
	}

	var settings tenant.OrgSettings
	if err := c.ShouldBindJSON(&settings); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	org.Settings = settings

	updated, err := h.store.Update(c.Request.Context(), orgIDStr, org)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update settings"})
		return
	}
	c.JSON(http.StatusOK, updated)
}
