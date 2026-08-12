package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SessionHandler provides session management endpoints.
type SessionHandler struct {
	pool *pgxpool.Pool
}

// NewSessionHandler creates a new SessionHandler.
func NewSessionHandler(pool *pgxpool.Pool) *SessionHandler {
	return &SessionHandler{pool: pool}
}

// hashToken returns the SHA-256 hex digest of the given token string.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// sessionRow is the DB row shape for user sessions.
type sessionRow struct {
	ID           string    `json:"id"`
	UserID       string    `json:"user_id"`
	IPAddress    string    `json:"ip_address"`
	UserAgent    string    `json:"user_agent"`
	CreatedAt    time.Time `json:"created_at"`
	LastActiveAt time.Time `json:"last_active_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	Revoked      bool      `json:"revoked"`
}

// sessionWithUser extends sessionRow with user info for admin views.
type sessionWithUser struct {
	sessionRow
	Username string `json:"user_name"`
	Email    string `json:"user_email"`
}

// ListSessions returns the authenticated user's active (non-revoked, non-expired) sessions.
//
// GET /api/v1/auth/sessions
func (h *SessionHandler) ListSessions(c *gin.Context) {
	userID, _ := c.Get("user_id")
	userIDStr, _ := userID.(string)

	rows, err := h.pool.Query(c.Request.Context(), `
		SELECT id, user_id, COALESCE(ip_address::text,''), COALESCE(user_agent,''),
		       created_at, last_active_at, expires_at, revoked
		FROM user_sessions
		WHERE user_id = $1
		  AND revoked = false
		  AND expires_at > NOW()
		ORDER BY last_active_at DESC`,
		userIDStr,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "セッション一覧の取得に失敗しました"})
		return
	}
	defer rows.Close()

	sessions := make([]sessionRow, 0)
	for rows.Next() {
		var s sessionRow
		if err := rows.Scan(&s.ID, &s.UserID, &s.IPAddress, &s.UserAgent,
			&s.CreatedAt, &s.LastActiveAt, &s.ExpiresAt, &s.Revoked); err != nil {
			continue
		}
		sessions = append(sessions, s)
	}
	if rows.Err() != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "セッションの読み取りに失敗しました"})
		return
	}

	c.JSON(http.StatusOK, sessions)
}

// ListAllSessions returns all active sessions across all users (admin only).
//
// GET /api/v1/admin/sessions
func (h *SessionHandler) ListAllSessions(c *gin.Context) {
	rows, err := h.pool.Query(c.Request.Context(), `
		SELECT s.id, s.user_id, COALESCE(s.ip_address::text,''),
		       COALESCE(NULLIF(s.user_agent,''), s.device_info->>'user_agent', ''),
		       s.created_at, s.last_active_at, s.expires_at, s.revoked,
		       COALESCE(u.full_name,''), COALESCE(u.email,'')
		FROM user_sessions s
		LEFT JOIN users u ON u.id = s.user_id
		ORDER BY s.last_active_at DESC
		LIMIT 500`,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "セッション一覧の取得に失敗しました"})
		return
	}
	defer rows.Close()

	sessions := make([]sessionWithUser, 0)
	for rows.Next() {
		var s sessionWithUser
		if err := rows.Scan(
			&s.ID, &s.UserID, &s.IPAddress, &s.UserAgent,
			&s.CreatedAt, &s.LastActiveAt, &s.ExpiresAt, &s.Revoked,
			&s.Username, &s.Email,
		); err != nil {
			continue
		}
		sessions = append(sessions, s)
	}
	if rows.Err() != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "セッションの読み取りに失敗しました"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"sessions": sessions})
}

// RevokeSession revokes a specific session by ID (user's own sessions only).
//
// DELETE /api/v1/auth/sessions/:id
func (h *SessionHandler) RevokeSession(c *gin.Context) {
	sessionID := c.Param("id")
	if sessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "セッションIDが必要です"})
		return
	}

	userID, _ := c.Get("user_id")
	userIDStr, _ := userID.(string)

	tag, err := h.pool.Exec(c.Request.Context(), `
		UPDATE user_sessions
		SET revoked = true, revoked_at = NOW()
		WHERE id = $1 AND user_id = $2 AND revoked = false`,
		sessionID, userIDStr,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "セッションの失効に失敗しました"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "セッションが見つからないか、アクセス権がありません"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "セッションを失効させました"})
}

// RevokeAllSessions revokes ALL sessions for the authenticated user (logout everywhere).
//
// DELETE /api/v1/auth/sessions
func (h *SessionHandler) RevokeAllSessions(c *gin.Context) {
	userID, _ := c.Get("user_id")
	userIDStr, _ := userID.(string)

	tag, err := h.pool.Exec(c.Request.Context(), `
		UPDATE user_sessions
		SET revoked = true, revoked_at = NOW()
		WHERE user_id = $1 AND revoked = false`,
		userIDStr,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "セッションの失効に失敗しました"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "すべてのセッションを失効させました",
		"revoked": tag.RowsAffected(),
	})
}

// AdminRevokeSession allows an admin to revoke any session by ID.
//
// DELETE /api/v1/admin/sessions/:id
func (h *SessionHandler) AdminRevokeSession(c *gin.Context) {
	sessionID := c.Param("id")
	if sessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "セッションIDが必要です"})
		return
	}

	tag, err := h.pool.Exec(c.Request.Context(), `
		UPDATE user_sessions
		SET revoked = true, revoked_at = NOW()
		WHERE id = $1 AND revoked = false`,
		sessionID,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "セッションの失効に失敗しました"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "セッションが見つかりません"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "セッションを失効させました"})
}

// AdminRevokeUserSessions revokes all sessions for a specific user (admin only).
//
// DELETE /api/v1/admin/users/:user_id/sessions
func (h *SessionHandler) AdminRevokeUserSessions(c *gin.Context) {
	targetUserID := c.Param("id")
	if targetUserID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ユーザーIDが必要です"})
		return
	}

	tag, err := h.pool.Exec(c.Request.Context(), `
		UPDATE user_sessions
		SET revoked = true, revoked_at = NOW()
		WHERE user_id = $1 AND revoked = false`,
		targetUserID,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "セッションの失効に失敗しました"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "ユーザーのすべてのセッションを失効させました",
		"revoked": tag.RowsAffected(),
	})
}
