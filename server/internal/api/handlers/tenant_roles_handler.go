package handlers

import (
	"net/http"

	"github.com/edr-platform/server/internal/store"
	"github.com/gin-gonic/gin"
)

// validTenantRoles は許可されたロール名のセットです。
var validTenantRoles = map[string]struct{}{
	"tenant_admin": {},
	"analyst":      {},
	"viewer":       {},
}

// TenantRolesHandler はテナントスコープのロール CRUD を提供します。
type TenantRolesHandler struct {
	store *store.TenantRoleStore
}

// NewTenantRolesHandler は TenantRolesHandler を生成します。
func NewTenantRolesHandler(s *store.TenantRoleStore) *TenantRolesHandler {
	return &TenantRolesHandler{store: s}
}

// List は指定テナントの全ロールエントリを返します。
// GET /api/v1/tenants/:id/roles
func (h *TenantRolesHandler) List(c *gin.Context) {
	tenantID := c.Param("id")

	roles, err := h.store.List(c.Request.Context(), tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ロール一覧の取得に失敗しました"})
		return
	}

	c.JSON(http.StatusOK, roles)
}

// Get は特定ユーザーのテナントロールを返します。
// GET /api/v1/tenants/:id/roles/:user_id
func (h *TenantRolesHandler) Get(c *gin.Context) {
	tenantID := c.Param("id")
	userID := c.Param("user_id")

	role, err := h.store.Get(c.Request.Context(), tenantID, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ロールの取得に失敗しました"})
		return
	}
	if role == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "ロールエントリが見つかりません"})
		return
	}

	c.JSON(http.StatusOK, role)
}

// Upsert はロールを追加または更新します。
// PUT /api/v1/tenants/:id/roles/:user_id
func (h *TenantRolesHandler) Upsert(c *gin.Context) {
	tenantID := c.Param("id")
	userID := c.Param("user_id")

	var req struct {
		Role string `json:"role" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "role フィールドは必須です"})
		return
	}

	if _, ok := validTenantRoles[req.Role]; !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "role は tenant_admin, analyst, viewer のいずれかを指定してください"})
		return
	}

	// context から granted_by (操作実行ユーザー) を取得
	grantedBy := ""
	if v, exists := c.Get("user_id"); exists {
		if s, ok := v.(string); ok {
			grantedBy = s
		}
	}

	role, err := h.store.Upsert(c.Request.Context(), tenantID, userID, req.Role, grantedBy)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ロールの更新に失敗しました"})
		return
	}

	c.JSON(http.StatusOK, role)
}

// Delete はロールエントリを削除します。
// DELETE /api/v1/tenants/:id/roles/:user_id
func (h *TenantRolesHandler) Delete(c *gin.Context) {
	tenantID := c.Param("id")
	userID := c.Param("user_id")

	if err := h.store.Delete(c.Request.Context(), tenantID, userID); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "ロールエントリが見つかりません"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}
