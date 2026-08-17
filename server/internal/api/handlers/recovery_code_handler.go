package handlers

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// RecoveryCodeHandler manages 2FA backup/recovery codes.
// Recovery codes are one-time use codes generated when MFA is enabled.
type RecoveryCodeHandler struct {
	pool *pgxpool.Pool
}

// NewRecoveryCodeHandler creates a new RecoveryCodeHandler.
func NewRecoveryCodeHandler(pool *pgxpool.Pool) *RecoveryCodeHandler {
	return &RecoveryCodeHandler{pool: pool}
}

// recoveryTableExists checks whether the recovery_codes table is present in the DB.
func (h *RecoveryCodeHandler) recoveryTableExists(c *gin.Context) bool {
	return tableIsThere(c.Request.Context(), h.pool, "recovery_codes")
}

// generateRecoveryCodes creates 10 random recovery codes in XXXX-XXXX-XXXX format.
func generateRecoveryCodes() ([]string, error) {
	codes := make([]string, 10)
	for i := 0; i < 10; i++ {
		buf := make([]byte, 6)
		if _, err := rand.Read(buf); err != nil {
			return nil, fmt.Errorf("failed to generate random bytes: %w", err)
		}
		hexStr := hex.EncodeToString(buf) // 12 hex chars
		codes[i] = fmt.Sprintf("%s-%s-%s",
			hexStr[0:4],
			hexStr[4:8],
			hexStr[8:12],
		)
	}
	return codes, nil
}

// hashCode returns the SHA-256 hex digest of a recovery code.
func hashCode(code string) string {
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}

// Generate generates 10 new recovery codes for the authenticated user.
// POST /api/v1/auth/recovery-codes/generate
func (h *RecoveryCodeHandler) Generate(c *gin.Context) {
	userID, _ := c.Get("user_id")
	userIDStr, _ := userID.(string)

	codes, err := generateRecoveryCodes()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "リカバリーコードの生成に失敗しました"})
		return
	}

	if h.pool != nil && h.recoveryTableExists(c) {
		now := time.Now().UTC()
		for _, code := range codes {
			hash := hashCode(code)
			if _, err := h.pool.Exec(c.Request.Context(),
				`INSERT INTO recovery_codes (user_id, code_hash, created_at) VALUES ($1, $2, $3)`,
				userIDStr, hash, now,
			); !WriteOK(c, err) {
				return
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"codes":   codes,
		"message": "これらのコードを安全な場所に保管してください",
	})
}

// Verify validates a recovery code and marks it as used.
// POST /api/v1/auth/recovery-codes/verify
func (h *RecoveryCodeHandler) Verify(c *gin.Context) {
	var req struct {
		Code string `json:"code" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "code が必要です"})
		return
	}

	userID, _ := c.Get("user_id")
	userIDStr, _ := userID.(string)

	if h.pool == nil || !h.recoveryTableExists(c) {
		c.JSON(http.StatusUnauthorized, gin.H{"valid": false})
		return
	}

	hash := hashCode(req.Code)

	var id string
	err := h.pool.QueryRow(c.Request.Context(),
		`SELECT id FROM recovery_codes
		 WHERE user_id = $1 AND code_hash = $2 AND used = false
		 LIMIT 1`,
		userIDStr, hash,
	).Scan(&id)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"valid": false})
		return
	}

	_, err = h.pool.Exec(c.Request.Context(),
		`UPDATE recovery_codes SET used = true, used_at = NOW() WHERE id = $1`,
		id,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "コードの更新に失敗しました"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"valid": true})
}

// ListStatus returns the count of total, used, and remaining recovery codes.
// GET /api/v1/auth/recovery-codes/status
func (h *RecoveryCodeHandler) ListStatus(c *gin.Context) {
	userID, _ := c.Get("user_id")
	userIDStr, _ := userID.(string)

	if h.pool == nil || !h.recoveryTableExists(c) {
		c.JSON(http.StatusOK, gin.H{"total": 0, "used": 0, "remaining": 0})
		return
	}

	var total, used int
	err := h.pool.QueryRow(c.Request.Context(),
		`SELECT
			COUNT(*),
			COUNT(*) FILTER (WHERE used = true)
		 FROM recovery_codes
		 WHERE user_id = $1`,
		userIDStr,
	).Scan(&total, &used)
	if err != nil {
		ReadFailure(c, err, gin.H{"total": 0, "used": 0, "remaining": 0})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"total":     total,
		"used":      used,
		"remaining": total - used,
	})
}

// Regenerate invalidates all existing codes and generates 10 new ones.
// POST /api/v1/auth/recovery-codes/regenerate
func (h *RecoveryCodeHandler) Regenerate(c *gin.Context) {
	userID, _ := c.Get("user_id")
	userIDStr, _ := userID.(string)

	codes, err := generateRecoveryCodes()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "リカバリーコードの生成に失敗しました"})
		return
	}

	if h.pool != nil && h.recoveryTableExists(c) {
		// Invalidate all existing codes
		if _, err := h.pool.Exec(c.Request.Context(),
			`UPDATE recovery_codes SET used = true WHERE user_id = $1 AND used = false`,
			userIDStr,
		); !WriteOK(c, err) {
			return
		}

		// Insert new codes
		now := time.Now().UTC()
		for _, code := range codes {
			hash := hashCode(code)
			if _, err := h.pool.Exec(c.Request.Context(),
				`INSERT INTO recovery_codes (user_id, code_hash, created_at) VALUES ($1, $2, $3)`,
				userIDStr, hash, now,
			); !WriteOK(c, err) {
				return
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"codes":   codes,
		"message": "これらのコードを安全な場所に保管してください",
	})
}
