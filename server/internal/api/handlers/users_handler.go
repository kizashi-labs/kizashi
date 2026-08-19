package handlers

import (
	"net/http"

	"github.com/edr-platform/server/internal/auth"
	"github.com/edr-platform/server/internal/metrics"
	"github.com/edr-platform/server/internal/store"
	"github.com/gin-gonic/gin"
)

// UsersHandler provides user management endpoints (admin only).
type UsersHandler struct {
	Store       *store.UserStore
	UserCache   *auth.UserStatusCache      // optional; invalidated on deactivation
	PolicyStore *store.PasswordPolicyStore // optional; enforces password policy on changes
}

func NewUsersHandler(s *store.UserStore) *UsersHandler {
	return &UsersHandler{Store: s}
}

var validUserRoles = map[string]bool{"admin": true, "analyst": true, "viewer": true}

// isValidUserRole reports whether r is an accepted user role.
func isValidUserRole(r string) bool { return validUserRoles[r] }

// ListUsers returns all users.
// GET /api/v1/users
func (h *UsersHandler) List(c *gin.Context) {
	users, err := h.Store.List(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ユーザー一覧の取得に失敗しました"})
		return
	}
	if users == nil {
		users = []*store.UserRow{}
	}
	c.JSON(http.StatusOK, gin.H{"data": users, "total": len(users)})
}

// CreateUser creates a new user (admin only).
// POST /api/v1/users
func (h *UsersHandler) Create(c *gin.Context) {
	var req struct {
		Email    string `json:"email" binding:"required"`
		Password string `json:"password" binding:"required"`
		FullName string `json:"full_name"`
		Role     string `json:"role"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "メールアドレスとパスワードが必要です"})
		return
	}

	if req.Role == "" {
		req.Role = "analyst"
	}
	if !isValidUserRole(req.Role) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "無効なロールです (admin/analyst/viewer)"})
		return
	}

	// Apply password policy when a store is configured
	if h.PolicyStore != nil {
		policy, err := h.PolicyStore.Get(c.Request.Context())
		if err == nil {
			if policyErr := h.PolicyStore.Validate(req.Password, policy); policyErr != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": policyErr.Error()})
				return
			}
		}
	}

	user, err := h.Store.Create(c.Request.Context(), req.Email, req.Password, req.FullName, req.Role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusCreated, user)
}

// UpdatePassword changes a user's password.
// PUT /api/v1/users/:id/password
func (h *UsersHandler) UpdatePassword(c *gin.Context) {
	id := c.Param("id")

	// Users can change their own password; admins can change anyone's
	callerID, _ := c.Get("user_id")
	callerRole, _ := c.Get("user_role")
	isSelf := callerID == id
	isAdmin := callerRole == "admin"

	if !isSelf && !isAdmin {
		c.JSON(http.StatusForbidden, gin.H{"error": "自分のパスワードのみ変更できます"})
		return
	}

	var req struct {
		CurrentPassword string `json:"current_password"`
		Password        string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "新しいパスワードが必要です"})
		return
	}
	// Apply password policy when a store is configured
	if h.PolicyStore != nil {
		policy, err := h.PolicyStore.Get(c.Request.Context())
		if err == nil {
			if policyErr := h.PolicyStore.Validate(req.Password, policy); policyErr != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": policyErr.Error()})
				return
			}
		}
		// If fetching policy fails, fall back to the hard-coded minimum
	}
	if len(req.Password) < 8 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "パスワードは8文字以上にしてください"})
		return
	}

	// Non-admin callers must provide their current password
	if isSelf && !isAdmin {
		if req.CurrentPassword == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "現在のパスワードを入力してください"})
			return
		}
		if err := h.Store.VerifyCurrentPassword(c.Request.Context(), id, req.CurrentPassword); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}
	}

	if err := h.Store.UpdatePassword(c.Request.Context(), id, req.Password); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "パスワードの更新に失敗しました"})
		return
	}
	// 初回パスワード変更フラグをクリア。
	//
	// **落ちると、変えたのに「変えてください」と言われ続けます。**
	// パスワード自体は更新できているので 500 にはしません（もう一度
	// 変えさせる方が悪い形です）—— 跡は件数に残します。
	if err := h.Store.ClearMustChangePassword(c.Request.Context(), id); err != nil {
		metrics.BackgroundFailed("password_change", err,
			"初回パスワード変更フラグを消せませんでした。変更後も変更を求められ続けます",
			"user_id", id)
	}
	c.JSON(http.StatusOK, gin.H{"message": "パスワードを更新しました"})
}

// DeactivateUser deactivates a user account (admin only).
// DELETE /api/v1/users/:id
func (h *UsersHandler) Deactivate(c *gin.Context) {
	id := c.Param("id")
	if err := h.Store.SetActive(c.Request.Context(), id, false); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ユーザーの無効化に失敗しました"})
		return
	}
	// Immediately evict from cache so next request gets rejected without waiting for TTL
	if h.UserCache != nil {
		h.UserCache.Invalidate(id)
	}
	c.JSON(http.StatusOK, gin.H{"message": "ユーザーを無効化しました", "id": id})
}

// Update updates a user's role and/or active status (admin only).
// PUT /api/v1/users/:id
func (h *UsersHandler) Update(c *gin.Context) {
	id := c.Param("id")

	var req struct {
		Role     *string `json:"role"`
		IsActive *bool   `json:"is_active"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "無効なリクエストです"})
		return
	}

	if req.Role != nil {
		validRoles := map[string]bool{"admin": true, "analyst": true, "viewer": true}
		if !validRoles[*req.Role] {
			c.JSON(http.StatusBadRequest, gin.H{"error": "無効なロールです (admin/analyst/viewer)"})
			return
		}
		if err := h.Store.UpdateRole(c.Request.Context(), id, *req.Role); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "ロールの更新に失敗しました"})
			return
		}
	}

	if req.IsActive != nil {
		if err := h.Store.SetActive(c.Request.Context(), id, *req.IsActive); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "ステータスの更新に失敗しました"})
			return
		}
		if h.UserCache != nil && !*req.IsActive {
			h.UserCache.Invalidate(id)
		}
	}

	user, err := h.Store.GetByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"message": "更新しました", "id": id})
		return
	}
	c.JSON(http.StatusOK, user)
}

// UpdateMe updates the authenticated user's own profile (full_name only).
// PATCH /api/v1/users/me
func (h *UsersHandler) UpdateMe(c *gin.Context) {
	userID, _ := c.Get("user_id")
	userIDStr, _ := userID.(string)

	var req struct {
		FullName string `json:"full_name"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "無効なリクエストです"})
		return
	}

	if err := h.Store.UpdateFullName(c.Request.Context(), userIDStr, req.FullName); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "プロフィールの更新に失敗しました"})
		return
	}

	user, err := h.Store.GetByID(c.Request.Context(), userIDStr)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"message": "更新しました"})
		return
	}
	c.JSON(http.StatusOK, user)
}

// Me returns the current authenticated user's profile.
// GET /api/v1/users/me
func (h *UsersHandler) Me(c *gin.Context) {
	userID, _ := c.Get("user_id")
	userIDStr, _ := userID.(string)

	// Env admin has no DB record
	if userIDStr == "admin" {
		c.JSON(http.StatusOK, gin.H{
			"id":    "admin",
			"email": "admin@localhost",
			"role":  "admin",
		})
		return
	}

	user, err := h.Store.GetByID(c.Request.Context(), userIDStr)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "ユーザーが見つかりません"})
		return
	}
	c.JSON(http.StatusOK, user)
}
