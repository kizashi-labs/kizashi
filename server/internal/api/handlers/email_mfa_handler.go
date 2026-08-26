package handlers

import (
	"bytes"
	"context"
	"fmt"
	"github.com/edr-platform/server/internal/mailhdr"
	"html/template"
	"net/http"
	"net/smtp"

	"github.com/edr-platform/server/internal/store"
	"github.com/gin-gonic/gin"
)

// ─── EmailSender interface ────────────────────────────────────────────────────

// EmailSender はメールOTP送信インターフェース。
// notification.EmailSender はアラート通知専用のため別途定義する。
type EmailSender interface {
	SendOTP(ctx context.Context, toEmail, toName, otp string) error
}

// ─── SMTPOTPSender (EmailSender の標準実装) ───────────────────────────────────

// SMTPOTPSenderConfig はSMTP設定を保持する。
type SMTPOTPSenderConfig struct {
	SMTPHost string
	SMTPPort string
	Username string
	Password string
	From     string
}

// SMTPOTPSender は net/smtp でOTPメールを送信する。
type SMTPOTPSender struct {
	cfg SMTPOTPSenderConfig
}

// NewSMTPOTPSender は SMTPOTPSender を作成する。
func NewSMTPOTPSender(cfg SMTPOTPSenderConfig) *SMTPOTPSender {
	return &SMTPOTPSender{cfg: cfg}
}

// SendOTP はOTPコードをメールで送信する。
func (s *SMTPOTPSender) SendOTP(ctx context.Context, toEmail, toName, otp string) error {
	subject := "[EDR Platform] メール認証コード"

	displayName := toName
	if displayName == "" {
		displayName = toEmail
	}

	body := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:20px;color:#333">
  <div style="background:#1D6FE8;color:white;padding:16px 20px;border-radius:8px 8px 0 0">
    <h2 style="margin:0;font-size:18px">EDR Platform</h2>
    <p style="margin:4px 0 0;opacity:0.9;font-size:14px">メール認証コード</p>
  </div>
  <div style="border:1px solid #ddd;border-top:none;padding:24px;border-radius:0 0 8px 8px">
    <p style="margin-top:0">%s 様</p>
    <p>以下の認証コードを入力してログインを完了してください。</p>
    <div style="text-align:center;margin:24px 0">
      <span style="display:inline-block;font-size:32px;font-weight:bold;letter-spacing:8px;
                   padding:12px 24px;background:#f5f5f5;border-radius:8px;font-family:monospace">
        %s
      </span>
    </div>
    <p style="color:#666;font-size:13px">このコードは10分間有効です。</p>
    <p style="color:#999;font-size:12px">
      このメールに心当たりがない場合は無視してください。
    </p>
  </div>
  <p style="font-size:12px;color:#999;text-align:center;margin-top:16px">
    このメールはEDR Platformから自動送信されています。
  </p>
</body>
</html>`,
		template.HTMLEscapeString(displayName),
		template.HTMLEscapeString(otp),
	)

	addr := s.cfg.SMTPHost + ":" + s.cfg.SMTPPort
	auth := smtp.PlainAuth("", s.cfg.Username, s.cfg.Password, s.cfg.SMTPHost)

	var msg bytes.Buffer
	msg.WriteString(fmt.Sprintf("From: EDR Platform <%s>\r\n", mailhdr.Sanitize(s.cfg.From)))
	msg.WriteString(fmt.Sprintf("To: %s\r\n", mailhdr.Sanitize(toEmail)))
	msg.WriteString(fmt.Sprintf("Subject: %s\r\n", mailhdr.Sanitize(subject)))
	msg.WriteString("MIME-Version: 1.0\r\n")
	msg.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
	msg.WriteString("\r\n")
	msg.WriteString(body)

	done := make(chan error, 1)
	go func() {
		done <- smtp.SendMail(addr, auth, s.cfg.From, []string{toEmail}, msg.Bytes())
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		return err
	}
}

// ─── smtpUnconfiguredSender (SMTP未設定時にエラーを返すフォールバック) ─────────

type smtpUnconfiguredSender struct{}

func (s *smtpUnconfiguredSender) SendOTP(_ context.Context, _, _, _ string) error {
	return fmt.Errorf("メール送信が設定されていません (SMTP_HOST未設定)")
}

// ─── EmailMFAHandler ──────────────────────────────────────────────────────────

// EmailMFAHandler はメールOTP MFAを管理するハンドラー。
type EmailMFAHandler struct {
	otpStore    *store.EmailOTPStore
	userStore   *store.UserStore
	emailSender EmailSender
	auth        *AuthHandler // generateToken / validatePreAuthToken を借用
}

// NewEmailMFAHandler は EmailMFAHandler を作成する。
// emailSender が nil の場合は smtpUnconfiguredSender を使用し、OTP送信時に503を返す。
func NewEmailMFAHandler(
	otpStore *store.EmailOTPStore,
	userStore *store.UserStore,
	emailSender EmailSender,
	auth *AuthHandler,
) *EmailMFAHandler {
	sender := emailSender
	if sender == nil {
		sender = &smtpUnconfiguredSender{}
	}
	return &EmailMFAHandler{
		otpStore:    otpStore,
		userStore:   userStore,
		emailSender: sender,
		auth:        auth,
	}
}

// SendOTP はOTPを生成してユーザーのメールアドレスに送信する。
// POST /api/v1/auth/mfa/email/send
// リクエストボディ: {"pre_auth_token": "..."}
func (h *EmailMFAHandler) SendOTP(c *gin.Context) {
	var req struct {
		PreAuthToken string `json:"pre_auth_token" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "pre_auth_token が必要です"})
		return
	}

	userID, _, err := h.auth.validatePreAuthToken(req.PreAuthToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "無効または期限切れのトークンです"})
		return
	}

	user, err := h.userStore.GetByID(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "ユーザーが見つかりません"})
		return
	}

	otp, err := h.otpStore.Generate(c.Request.Context(), userID, "mfa")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "OTPの生成に失敗しました"})
		return
	}

	if err := h.emailSender.SendOTP(c.Request.Context(), user.Email, user.FullName, otp); err != nil {
		if err.Error() == "メール送信が設定されていません (SMTP_HOST未設定)" {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "メールMFAはSMTPが設定されていないため利用できません"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "メールの送信に失敗しました"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "認証コードを送信しました"})
}

// VerifyOTP はOTPを検証し、成功時にフルJWTを返す。
// POST /api/v1/auth/mfa/email/verify
// リクエストボディ: {"pre_auth_token": "...", "code": "123456"}
func (h *EmailMFAHandler) VerifyOTP(c *gin.Context) {
	var req struct {
		PreAuthToken string `json:"pre_auth_token" binding:"required"`
		Code         string `json:"code" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "pre_auth_token と code が必要です"})
		return
	}

	userID, _, err := h.auth.validatePreAuthToken(req.PreAuthToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "無効または期限切れのトークンです"})
		return
	}

	if err := h.otpStore.Verify(c.Request.Context(), userID, req.Code, "mfa"); err != nil {
		if err == store.ErrExpired {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "認証コードが期限切れまたは無効です"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "OTPの検証に失敗しました"})
		return
	}

	user, err := h.userStore.GetByID(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "ユーザーが見つかりません"})
		return
	}

	tenantID := user.TenantID
	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000001"
	}

	token, _, err := h.auth.generateToken(userID, user.Role, tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "トークンの生成に失敗しました"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token":      token,
		"expires_in": 86400,
		"user": gin.H{
			"id":          user.ID,
			"email":       user.Email,
			"full_name":   user.FullName,
			"role":        user.Role,
			"mfa_enabled": user.MFAEnabled,
		},
	})
}

// EnableEmailMFA はユーザーの mfa_type を 'email' に変更する。
// POST /api/v1/auth/mfa/email/enable
// 認証済みユーザーのみ (JWTミドルウェア必須)
func (h *EmailMFAHandler) EnableEmailMFA(c *gin.Context) {
	userID, _ := c.Get("user_id")
	userIDStr, _ := userID.(string)

	if err := h.userStore.SetMFAType(c.Request.Context(), userIDStr, "email"); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "メールMFAの有効化に失敗しました"})
		return
	}

	// mfa_enabled フラグも立てる
	if err := h.userStore.EnableMFA(c.Request.Context(), userIDStr); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "MFAの有効化に失敗しました"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "メールOTP MFAを有効化しました", "mfa_type": "email"})
}

// DisableEmailMFA は mfa_type を 'none' に変更する。
// POST /api/v1/auth/mfa/email/disable
// 認証済みユーザーのみ (JWTミドルウェア必須)
func (h *EmailMFAHandler) DisableEmailMFA(c *gin.Context) {
	userID, _ := c.Get("user_id")
	userIDStr, _ := userID.(string)

	if err := h.userStore.SetMFAType(c.Request.Context(), userIDStr, "none"); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "メールMFAの無効化に失敗しました"})
		return
	}

	if err := h.userStore.DisableMFA(c.Request.Context(), userIDStr); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "MFAの無効化に失敗しました"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "メールOTP MFAを無効化しました", "mfa_type": "none"})
}
