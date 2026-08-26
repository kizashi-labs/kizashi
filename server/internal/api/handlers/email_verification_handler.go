package handlers

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/edr-platform/server/internal/email"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

// EmailVerificationHandler manages email address verification.
type EmailVerificationHandler struct {
	pool    *pgxpool.Pool
	baseURL string
	Mailer  *email.Sender
}

// NewEmailVerificationHandler creates a new EmailVerificationHandler.
func NewEmailVerificationHandler(pool *pgxpool.Pool, baseURL string, mailer *email.Sender) *EmailVerificationHandler {
	return &EmailVerificationHandler{
		pool:    pool,
		baseURL: baseURL,
		Mailer:  mailer,
	}
}

// generateVerificationToken generates a 32-byte crypto-random hex token.
func generateVerificationToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// SendVerification handles POST /api/v1/auth/email-verification/send
// Generates a verification token for the authenticated user and sends a verification email.
func (h *EmailVerificationHandler) SendVerification(c *gin.Context) {
	userIDVal, _ := c.Get("user_id")
	userID, _ := userIDVal.(string)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "認証が必要です"})
		return
	}

	// Fetch user email and current verification status
	var email string
	var isVerified bool
	err := h.pool.QueryRow(c.Request.Context(),
		`SELECT email, COALESCE(email_verified, false) FROM users WHERE id=$1::uuid`,
		userID,
	).Scan(&email, &isVerified)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "ユーザーが見つかりません"})
		return
	}
	if isVerified {
		c.JSON(http.StatusOK, gin.H{"message": "メールアドレスは既に確認済みです"})
		return
	}

	rawToken, err := generateVerificationToken()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "トークンの生成に失敗しました"})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(rawToken), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "トークンのハッシュ化に失敗しました"})
		return
	}

	// Upsert token — one active token per user
	_, err = h.pool.Exec(c.Request.Context(),
		`INSERT INTO email_verification_tokens (user_id, token_hash)
		 VALUES ($1::uuid, $2)
		 ON CONFLICT (user_id) DO UPDATE
		   SET token_hash=$2, expires_at=NOW() + INTERVAL '24 hours', created_at=NOW()`,
		userID, string(hash),
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "トークンの保存に失敗しました"})
		return
	}

	verifyLink := fmt.Sprintf("%s/auth/verify-email?token=%s", h.baseURL, rawToken)
	go func() {
		mailCtx, mailCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer mailCancel()
		if err := h.Mailer.SendEmailVerification(mailCtx, email, verifyLink); err != nil {
			slog.Warn("メール確認メールの送信に失敗しました", "email", email, "error", err)
		}
	}()

	c.JSON(http.StatusOK, gin.H{"message": "確認メールを送信しました"})
}

// ConfirmVerification handles POST /api/v1/auth/email-verification/confirm
// Validates the token and marks the user's email as verified.
// Body: {"token": "<raw token>"}
func (h *EmailVerificationHandler) ConfirmVerification(c *gin.Context) {
	var req struct {
		Token string `json:"token" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tokenが必要です"})
		return
	}

	// Fetch all non-expired tokens and find the matching one via bcrypt
	rows, err := h.pool.Query(c.Request.Context(),
		`SELECT id, user_id::text, token_hash FROM email_verification_tokens
		 WHERE expires_at > NOW()
		 ORDER BY created_at DESC`,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "トークン検索に失敗しました"})
		return
	}
	defer rows.Close()

	type tokenRow struct {
		id     string
		userID string
		hash   string
	}
	var candidates []tokenRow
	for rows.Next() {
		var r tokenRow
		if err := rows.Scan(&r.id, &r.userID, &r.hash); err != nil {
			continue
		}
		candidates = append(candidates, r)
	}
	if err := rows.Err(); err != nil {
		slog.Error("rows.Err: 結果の読み出しが途中で失敗しました", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "トークン検索に失敗しました"})
		return
	}
	rows.Close()

	var matchedUserID, matchedTokenID string
	for _, r := range candidates {
		if bcrypt.CompareHashAndPassword([]byte(r.hash), []byte(req.Token)) == nil {
			matchedUserID = r.userID
			matchedTokenID = r.id
			break
		}
	}

	if matchedUserID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "無効または期限切れのトークンです"})
		return
	}

	// Mark user's email as verified
	_, err = h.pool.Exec(c.Request.Context(),
		`UPDATE users SET email_verified=true, email_verified_at=NOW(), updated_at=NOW()
		 WHERE id=$1::uuid`,
		matchedUserID,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "メールアドレスの確認に失敗しました"})
		return
	}

	// Delete consumed token
	if _, err := h.pool.Exec(c.Request.Context(),
		`DELETE FROM email_verification_tokens WHERE id=$1`, matchedTokenID,
	); !WriteOK(c, err) {
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "メールアドレスを確認しました"})
}

// GetStatus handles GET /api/v1/auth/email-verification/status
// Returns the verification status of the authenticated user.
func (h *EmailVerificationHandler) GetStatus(c *gin.Context) {
	userIDVal, _ := c.Get("user_id")
	userID, _ := userIDVal.(string)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "認証が必要です"})
		return
	}

	var isVerified bool
	err := h.pool.QueryRow(c.Request.Context(),
		`SELECT COALESCE(email_verified, false) FROM users WHERE id=$1::uuid`, userID,
	).Scan(&isVerified)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "ユーザーが見つかりません"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"email_verified": isVerified})
}
