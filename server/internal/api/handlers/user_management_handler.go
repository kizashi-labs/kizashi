package handlers

import (
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

// UserManagementHandler provides admin-level user management endpoints
// at /api/v1/admin/users and self-service profile endpoints at /api/v1/profile.
type UserManagementHandler struct {
	pool      *pgxpool.Pool
	jwtSecret string
}

// NewUserManagementHandler creates a new UserManagementHandler.
func NewUserManagementHandler(pool *pgxpool.Pool, jwtSecret string) *UserManagementHandler {
	return &UserManagementHandler{pool: pool, jwtSecret: jwtSecret}
}

// adminUserRow is the full user record returned by admin endpoints.
type adminUserRow struct {
	ID               string     `json:"id"`
	Username         string     `json:"username"`
	Email            string     `json:"email"`
	FullName         string     `json:"full_name"`
	Role             string     `json:"role"`
	Enabled          bool       `json:"enabled"`
	MFAEnabled       bool       `json:"mfa_enabled"`
	LastLogin        *time.Time `json:"last_login,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	AvatarURL        string     `json:"avatar_url,omitempty"`
	LoginCount       int        `json:"login_count"`
	FailedLoginCount int        `json:"failed_login_count"`
	LockedUntil      *time.Time `json:"locked_until,omitempty"`
}

// fetchUser fetches a single user row by ID.
func (h *UserManagementHandler) fetchUser(c *gin.Context, id string) (*adminUserRow, error) {
	var u adminUserRow
	err := h.pool.QueryRow(c.Request.Context(), `
		SELECT id,
		       COALESCE(email,''),
		       COALESCE(email,''),
		       COALESCE(full_name,''),
		       COALESCE(role,'analyst'),
		       COALESCE(is_active, true),
		       COALESCE(mfa_enabled, false),
		       last_login,
		       created_at,
		       COALESCE(avatar_url,''),
		       COALESCE(login_count,0),
		       COALESCE(failed_login_count,0),
		       locked_until
		FROM users WHERE id = $1`, id,
	).Scan(
		&u.ID, &u.Username, &u.Email, &u.FullName, &u.Role,
		&u.Enabled, &u.MFAEnabled, &u.LastLogin, &u.CreatedAt,
		&u.AvatarURL, &u.LoginCount, &u.FailedLoginCount, &u.LockedUntil,
	)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// ─── Admin: List Users ──────────────────────────────────────────────────────

// ListUsers returns all users with optional filtering.
// GET /api/v1/admin/users?search=&role=&limit=20&offset=0
func (h *UserManagementHandler) ListUsers(c *gin.Context) {
	search := c.Query("search")
	role := c.Query("role")
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if limit <= 0 || limit > 200 {
		limit = 20
	}
	if offset < 0 {
		offset = 0
	}

	rows, err := h.pool.Query(c.Request.Context(), `
		SELECT id,
		       COALESCE(email,''),
		       COALESCE(email,''),
		       COALESCE(full_name,''),
		       COALESCE(role,'analyst'),
		       COALESCE(is_active, true),
		       COALESCE(mfa_enabled, false),
		       last_login,
		       created_at,
		       COALESCE(avatar_url,''),
		       COALESCE(login_count,0),
		       COALESCE(failed_login_count,0),
		       locked_until
		FROM users
		WHERE ($1 = '' OR email ILIKE '%' || $1 || '%' OR COALESCE(full_name,'') ILIKE '%' || $1 || '%')
		  AND ($2 = '' OR role = $2)
		ORDER BY created_at DESC
		LIMIT $3 OFFSET $4`,
		search, role, limit, offset)
	if err != nil {
		slog.Warn("user list query failed", "error", err)
		ReadFailure(c, err, gin.H{"users": []adminUserRow{}, "total": 0})
		return
	}
	defer rows.Close()

	var users []adminUserRow
	for rows.Next() {
		var u adminUserRow
		if err := rows.Scan(
			&u.ID, &u.Username, &u.Email, &u.FullName, &u.Role,
			&u.Enabled, &u.MFAEnabled, &u.LastLogin, &u.CreatedAt,
			&u.AvatarURL, &u.LoginCount, &u.FailedLoginCount, &u.LockedUntil,
		); err != nil {
			continue
		}
		users = append(users, u)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("user list query failed", "error", err)
		ReadFailure(c, err, gin.H{"users": []adminUserRow{}, "total": 0})
		return
	}
	if users == nil {
		users = []adminUserRow{}
	}

	var total int
	if !ReadOK(c, h.pool.QueryRow(c.Request.Context(),
		`SELECT COUNT(*) FROM users
			 WHERE ($1 = '' OR email ILIKE '%' || $1 || '%' OR COALESCE(full_name,'') ILIKE '%' || $1 || '%')
			   AND ($2 = '' OR role = $2)`,
		search, role,
	).Scan(&total)) {
		return
	}

	c.JSON(http.StatusOK, gin.H{"users": users, "total": total})
}

// ─── Admin: Create User ─────────────────────────────────────────────────────

// CreateUser creates a new user (admin only).
// POST /api/v1/admin/users
func (h *UserManagementHandler) CreateUser(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
		Email    string `json:"email" binding:"required"`
		Password string `json:"password" binding:"required"`
		Role     string `json:"role"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "email and password are required"})
		return
	}
	if req.Role == "" {
		req.Role = "analyst"
	}
	validRoles := map[string]bool{"admin": true, "analyst": true, "viewer": true}
	if !validRoles[req.Role] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid role: must be admin, analyst, or viewer"})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), 12)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to hash password"})
		return
	}

	fullName := req.Username
	if fullName == "" {
		fullName = req.Email
	}

	var u adminUserRow
	err = h.pool.QueryRow(c.Request.Context(), `
		INSERT INTO users (email, password_hash, full_name, role, is_active, must_change_password)
		VALUES ($1, $2, $3, $4, true, false)
		RETURNING id,
		          COALESCE(email,''),
		          COALESCE(email,''),
		          COALESCE(full_name,''),
		          COALESCE(role,'analyst'),
		          COALESCE(is_active,true),
		          COALESCE(mfa_enabled,false),
		          last_login,
		          created_at,
		          COALESCE(avatar_url,''),
		          COALESCE(login_count,0),
		          COALESCE(failed_login_count,0),
		          locked_until`,
		req.Email, string(hash), fullName, req.Role,
	).Scan(
		&u.ID, &u.Username, &u.Email, &u.FullName, &u.Role,
		&u.Enabled, &u.MFAEnabled, &u.LastLogin, &u.CreatedAt,
		&u.AvatarURL, &u.LoginCount, &u.FailedLoginCount, &u.LockedUntil,
	)
	if err != nil {
		slog.Warn("create user failed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create user"})
		return
	}
	c.JSON(http.StatusCreated, u)
}

// ─── Admin: Get User ────────────────────────────────────────────────────────

// GetUser returns a single user by ID.
// GET /api/v1/admin/users/:id
func (h *UserManagementHandler) GetUser(c *gin.Context) {
	id := c.Param("id")
	u, err := h.fetchUser(c, id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}
	c.JSON(http.StatusOK, u)
}

// ─── Admin: Update User ─────────────────────────────────────────────────────

// UpdateUser updates email, role, and/or enabled status.
// PUT /api/v1/admin/users/:id
func (h *UserManagementHandler) UpdateUser(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Email   *string `json:"email"`
		Role    *string `json:"role"`
		Enabled *bool   `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	if req.Role != nil {
		validRoles := map[string]bool{"admin": true, "analyst": true, "viewer": true}
		if !validRoles[*req.Role] {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid role"})
			return
		}
		if _, err := h.pool.Exec(c.Request.Context(),
			"UPDATE users SET role = $2, updated_at = NOW() WHERE id = $1", id, *req.Role); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update role"})
			return
		}
	}
	if req.Email != nil {
		if _, err := h.pool.Exec(c.Request.Context(),
			"UPDATE users SET email = $2, updated_at = NOW() WHERE id = $1", id, *req.Email); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update email"})
			return
		}
	}
	if req.Enabled != nil {
		if _, err := h.pool.Exec(c.Request.Context(),
			"UPDATE users SET is_active = $2, updated_at = NOW() WHERE id = $1", id, *req.Enabled); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update status"})
			return
		}
	}

	u, err := h.fetchUser(c, id)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"message": "updated", "id": id})
		return
	}
	c.JSON(http.StatusOK, u)
}

// ─── Admin: Delete User ─────────────────────────────────────────────────────

// DeleteUser soft-deletes (sets is_active=false) or hard-deletes a user.
// DELETE /api/v1/admin/users/:id?hard=true
func (h *UserManagementHandler) DeleteUser(c *gin.Context) {
	id := c.Param("id")
	hardDelete := c.Query("hard") == "true"

	if hardDelete {
		if _, err := h.pool.Exec(c.Request.Context(), "DELETE FROM users WHERE id = $1", id); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete user"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "user deleted", "id": id})
		return
	}

	if _, err := h.pool.Exec(c.Request.Context(),
		"UPDATE users SET is_active = false, updated_at = NOW() WHERE id = $1", id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to deactivate user"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "user deactivated", "id": id})
}

// ─── Admin: Reset Password ──────────────────────────────────────────────────

// ResetPassword sets a new password for a user (admin-initiated).
// POST /api/v1/admin/users/:id/reset-password
func (h *UserManagementHandler) ResetPassword(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		NewPassword string `json:"new_password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "new_password is required"})
		return
	}
	if len(req.NewPassword) < 8 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "password must be at least 8 characters"})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), 12)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to hash password"})
		return
	}
	if _, err := h.pool.Exec(c.Request.Context(),
		"UPDATE users SET password_hash = $2, must_change_password = false, updated_at = NOW() WHERE id = $1",
		id, string(hash)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to reset password"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "password reset successfully"})
}

// ─── Admin: Change Role ─────────────────────────────────────────────────────

// ChangeRole updates the role for a user.
// PUT /api/v1/admin/users/:id/role
func (h *UserManagementHandler) ChangeRole(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Role string `json:"role" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "role is required"})
		return
	}
	validRoles := map[string]bool{"admin": true, "analyst": true, "viewer": true}
	if !validRoles[req.Role] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid role: must be admin, analyst, or viewer"})
		return
	}
	if _, err := h.pool.Exec(c.Request.Context(),
		"UPDATE users SET role = $2, updated_at = NOW() WHERE id = $1", id, req.Role); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update role"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "role updated", "id": id, "role": req.Role})
}

// ─── Admin: Toggle MFA Requirement ─────────────────────────────────────────

// ToggleMFA enables or disables MFA for a user.
// PUT /api/v1/admin/users/:id/mfa
func (h *UserManagementHandler) ToggleMFA(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	var err error
	if req.Enabled {
		_, err = h.pool.Exec(c.Request.Context(),
			"UPDATE users SET mfa_enabled = true, updated_at = NOW() WHERE id = $1", id)
	} else {
		_, err = h.pool.Exec(c.Request.Context(),
			"UPDATE users SET mfa_enabled = false, mfa_secret = NULL, updated_at = NOW() WHERE id = $1", id)
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update MFA"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "MFA setting updated", "id": id, "mfa_enabled": req.Enabled})
}

// ─── Admin: User Stats ──────────────────────────────────────────────────────

// GetStats returns aggregate user statistics.
// GET /api/v1/admin/users/stats
func (h *UserManagementHandler) GetStats(c *gin.Context) {
	type statsResult struct {
		Total           int `json:"total"`
		Admins          int `json:"admins"`
		Analysts        int `json:"analysts"`
		Viewers         int `json:"viewers"`
		MFAEnabledCount int `json:"mfa_enabled_count"`
		ActiveToday     int `json:"active_today"`
	}
	var stats statsResult

	err := h.pool.QueryRow(c.Request.Context(), `
		SELECT
		  COUNT(*)                                                         AS total,
		  COUNT(*) FILTER (WHERE role = 'admin')                           AS admins,
		  COUNT(*) FILTER (WHERE role = 'analyst')                         AS analysts,
		  COUNT(*) FILTER (WHERE role = 'viewer')                          AS viewers,
		  COUNT(*) FILTER (WHERE COALESCE(mfa_enabled, false) = true)      AS mfa_enabled_count,
		  COUNT(*) FILTER (WHERE last_login >= NOW() - INTERVAL '1 day')  AS active_today
		FROM users`).Scan(
		&stats.Total, &stats.Admins, &stats.Analysts,
		&stats.Viewers, &stats.MFAEnabledCount, &stats.ActiveToday,
	)
	if err != nil {
		slog.Warn("user stats query failed", "error", err)
		ReadFailure(c, err, statsResult{})
		return
	}
	c.JSON(http.StatusOK, stats)
}

// ─── Profile: Get Own Profile ───────────────────────────────────────────────

// GetProfile returns the current user's profile from JWT claims.
// GET /api/v1/profile
func (h *UserManagementHandler) GetProfile(c *gin.Context) {
	userID, _ := c.Get("user_id")
	uid, _ := userID.(string)

	if uid == "admin" {
		c.JSON(http.StatusOK, gin.H{
			"id":    "admin",
			"email": "admin@localhost",
			"role":  "admin",
		})
		return
	}

	u, err := h.fetchUser(c, uid)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}
	c.JSON(http.StatusOK, u)
}

// ─── Profile: Update Own Profile ────────────────────────────────────────────

// UpdateProfile allows users to update their own email/full_name (not role/enabled).
// PUT /api/v1/profile
func (h *UserManagementHandler) UpdateProfile(c *gin.Context) {
	userID, _ := c.Get("user_id")
	uid, _ := userID.(string)

	var req struct {
		Email    *string `json:"email"`
		FullName *string `json:"full_name"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	if req.Email != nil {
		if _, err := h.pool.Exec(c.Request.Context(),
			"UPDATE users SET email = $2, updated_at = NOW() WHERE id = $1", uid, *req.Email); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update email"})
			return
		}
	}
	if req.FullName != nil {
		if _, err := h.pool.Exec(c.Request.Context(),
			"UPDATE users SET full_name = $2, updated_at = NOW() WHERE id = $1", uid, *req.FullName); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update full name"})
			return
		}
	}

	u, err := h.fetchUser(c, uid)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"message": "profile updated"})
		return
	}
	c.JSON(http.StatusOK, u)
}

// ─── Profile: Change Own Password ───────────────────────────────────────────

// ChangePassword allows users to change their own password with bcrypt verification.
// PUT /api/v1/profile/password
func (h *UserManagementHandler) ChangePassword(c *gin.Context) {
	userID, _ := c.Get("user_id")
	uid, _ := userID.(string)

	var req struct {
		CurrentPassword string `json:"current_password" binding:"required"`
		NewPassword     string `json:"new_password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "current_password and new_password are required"})
		return
	}
	if len(req.NewPassword) < 8 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "new password must be at least 8 characters"})
		return
	}

	var currentHash string
	if err := h.pool.QueryRow(c.Request.Context(),
		"SELECT COALESCE(password_hash,'') FROM users WHERE id = $1", uid,
	).Scan(&currentHash); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}
	if currentHash == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no password set"})
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(currentHash), []byte(req.CurrentPassword)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "current password is incorrect"})
		return
	}

	newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), 12)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to hash password"})
		return
	}
	if _, err := h.pool.Exec(c.Request.Context(),
		"UPDATE users SET password_hash = $2, must_change_password = false, updated_at = NOW() WHERE id = $1",
		uid, string(newHash)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update password"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "password updated successfully"})
}
