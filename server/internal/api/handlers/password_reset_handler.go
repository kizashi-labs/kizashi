package handlers

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"time"
	"unicode"

	"github.com/edr-platform/server/internal/email"
	"github.com/edr-platform/server/internal/store"
	"github.com/gin-gonic/gin"
)

// PasswordResetHandler はパスワードリセット機能を管理するハンドラー。
type PasswordResetHandler struct {
	resetStore *store.PasswordResetStore
	userStore  *store.UserStore
	baseURL    string
	Mailer     *email.Sender
}

// NewPasswordResetHandler は PasswordResetHandler を作成する。
func NewPasswordResetHandler(resetStore *store.PasswordResetStore, userStore *store.UserStore, baseURL string, mailer *email.Sender) *PasswordResetHandler {
	return &PasswordResetHandler{
		resetStore: resetStore,
		userStore:  userStore,
		baseURL:    baseURL,
		Mailer:     mailer,
	}
}

// validateNewPassword はパスワードの最小要件を検証する。
// 最低8文字、英字と数字を含む必要がある。
func validateNewPassword(pw string) error {
	if len(pw) < 8 {
		return fmt.Errorf("パスワードは8文字以上必要です")
	}
	hasLetter := false
	hasDigit := false
	for _, r := range pw {
		if unicode.IsLetter(r) {
			hasLetter = true
		}
		if unicode.IsDigit(r) {
			hasDigit = true
		}
	}
	if !hasLetter || !hasDigit {
		return fmt.Errorf("パスワードには英字と数字の両方を含める必要があります")
	}
	return nil
}

var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

// RequestReset はパスワードリセットリンクをメールで送信する。
// POST /api/v1/auth/password-reset/request
// Body: {"email": "user@example.com"}
// メールの存在有無に関わらず常に200を返す (メール存在漏洩を防ぐ)。
func (h *PasswordResetHandler) RequestReset(c *gin.Context) {
	var req struct {
		Email string `json:"email" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "メールアドレスが必要です"})
		return
	}

	if !emailRegex.MatchString(req.Email) {
		// 不正な形式でも200を返す
		c.JSON(http.StatusOK, gin.H{"message": "メールを送信しました"})
		return
	}

	// ユーザー検索 — 見つからなくても200を返す
	userObj, err := h.userStore.GetByEmail(c.Request.Context(), req.Email)
	if err == nil && userObj != nil {
		userID := userObj.ID
		fullName := userObj.FullName
		rawToken, err := h.resetStore.Create(c.Request.Context(), userID)
		if err == nil {
			resetLink := fmt.Sprintf("%s/auth/reset-password?token=%s", h.baseURL, rawToken)
			go func() {
				mailCtx, mailCancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer mailCancel()
				if err := h.Mailer.SendPasswordReset(mailCtx, req.Email, fullName, resetLink); err != nil {
					slog.Warn("パスワードリセットメールの送信に失敗しました", "email", req.Email, "error", err)
				}
			}()
		} else {
			slog.Warn("パスワードリセットトークン生成エラー", "error", err)
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "メールを送信しました"})
}

// ConfirmReset はトークンを検証し、パスワードを更新する。
// POST /api/v1/auth/password-reset/confirm
// Body: {"token": "<raw>", "new_password": "..."}
func (h *PasswordResetHandler) ConfirmReset(c *gin.Context) {
	var req struct {
		Token       string `json:"token" binding:"required"`
		NewPassword string `json:"new_password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "token と new_password が必要です"})
		return
	}

	if err := validateNewPassword(req.NewPassword); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID, err := h.resetStore.Verify(c.Request.Context(), req.Token)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "無効または期限切れのトークンです"})
		return
	}

	if err := h.userStore.UpdatePassword(c.Request.Context(), userID, req.NewPassword); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "パスワードの更新に失敗しました"})
		return
	}

	if err := h.resetStore.MarkUsed(c.Request.Context(), req.Token); err != nil {
		// ログに記録するが、パスワードは既に更新済みなので成功とみなす
		slog.Warn("MarkUsedエラー", "error", err)
	}

	c.JSON(http.StatusOK, gin.H{"message": "パスワードを変更しました"})
}
