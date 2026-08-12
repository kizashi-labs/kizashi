package handlers

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/edr-platform/server/internal/email"
	"github.com/edr-platform/server/internal/store"
	"github.com/gin-gonic/gin"
)

// InvitationHandler handles user invitation endpoints.
type InvitationHandler struct {
	Store     *store.InvitationStore
	UserStore *store.UserStore
	BaseURL   string
	Mailer    *email.Sender
}

func NewInvitationHandler(s *store.InvitationStore, us *store.UserStore, baseURL string, mailer *email.Sender) *InvitationHandler {
	return &InvitationHandler{Store: s, UserStore: us, BaseURL: baseURL, Mailer: mailer}
}

// ─── Admin: Create invitation ─────────────────────────────────────────────────

// POST /api/v1/admin/invitations
func (h *InvitationHandler) Create(c *gin.Context) {
	var req struct {
		Email    string `json:"email" binding:"required"`
		Role     string `json:"role"`
		TenantID string `json:"tenant_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "メールアドレスが必要です"})
		return
	}

	if req.Role == "" {
		req.Role = "analyst"
	}
	validRoles := map[string]bool{"admin": true, "analyst": true, "viewer": true}
	if !validRoles[req.Role] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "無効なロールです (admin/analyst/viewer)"})
		return
	}

	invitedByID, _ := c.Get("user_id")
	invitedByStr, _ := invitedByID.(string)

	rawToken, err := h.Store.Create(c.Request.Context(), req.Email, req.Role, req.TenantID, invitedByStr)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}

	// Send invitation email (non-blocking; log errors but don't fail the API call)
	inviteURL := fmt.Sprintf("%s/auth/accept-invite?token=%s", h.BaseURL, rawToken)
	go func() {
		mailCtx, mailCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer mailCancel()
		if err := h.Mailer.SendInvitation(mailCtx, req.Email, inviteURL); err != nil {
			slog.Warn("招待メールの送信に失敗しました", "email", req.Email, "error", err)
		}
	}()

	c.JSON(http.StatusCreated, gin.H{
		"message":    "招待を送信しました",
		"email":      req.Email,
		"invite_url": inviteURL,
	})
}

// ─── Admin: List pending invitations ─────────────────────────────────────────

// GET /api/v1/admin/invitations
func (h *InvitationHandler) List(c *gin.Context) {
	invitations, err := h.Store.ListPending(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "招待一覧の取得に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": invitations, "total": len(invitations)})
}

// ─── Admin: Revoke invitation ─────────────────────────────────────────────────

// DELETE /api/v1/admin/invitations/:id
func (h *InvitationHandler) Delete(c *gin.Context) {
	id := c.Param("id")
	if err := h.Store.Delete(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "招待の削除に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "招待を削除しました", "id": id})
}

// ─── Public: Get invite info ──────────────────────────────────────────────────

// GET /api/v1/auth/invite/info?token=<raw>
func (h *InvitationHandler) Info(c *gin.Context) {
	rawToken := c.Query("token")
	if rawToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "トークンが必要です"})
		return
	}

	inv, err := h.Store.FindByToken(c.Request.Context(), rawToken)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "招待が見つかりません。期限切れか無効なトークンです"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"email": inv.Email,
		"role":  inv.Role,
	})
}

// ─── Public: Accept invitation ────────────────────────────────────────────────

// POST /api/v1/auth/invite/accept
// Body: { token, full_name, password }
func (h *InvitationHandler) Accept(c *gin.Context) {
	var req struct {
		Token    string `json:"token" binding:"required"`
		FullName string `json:"full_name"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "トークンとパスワードが必要です"})
		return
	}

	if len(req.Password) < 8 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "パスワードは8文字以上にしてください"})
		return
	}

	inv, err := h.Store.FindByToken(c.Request.Context(), req.Token)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "招待が見つかりません。期限切れか無効なトークンです"})
		return
	}

	// Create the user account; must_change_password = false since they set it here
	user, err := h.UserStore.CreateFromInvitation(c.Request.Context(), inv.Email, req.Password, req.FullName, inv.Role, inv.TenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}

	// Mark invitation as accepted
	if err := h.Store.Accept(c.Request.Context(), inv.ID); err != nil {
		slog.Warn("招待の受諾フラグ更新に失敗しました", "id", inv.ID, "error", err)
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "アカウントを作成しました。ログインしてください",
		"user_id": user.ID,
		"email":   user.Email,
	})
}
