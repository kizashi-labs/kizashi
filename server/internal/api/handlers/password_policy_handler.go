package handlers

import (
	"log/slog"
	"net/http"
	"unicode"

	"github.com/edr-platform/server/internal/store"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PasswordPolicyHandler handles CRUD for the global password policy.
// It supports both the legacy store-based approach and the new pool-based approach.
type PasswordPolicyHandler struct {
	// Legacy store-based fields (backward compat)
	Store *store.PasswordPolicyStore
	// Pool-based field for new endpoints
	pool *pgxpool.Pool
}

// NewPasswordPolicyHandler creates a handler backed by the legacy store.
func NewPasswordPolicyHandler(s *store.PasswordPolicyStore) *PasswordPolicyHandler {
	return &PasswordPolicyHandler{Store: s}
}

// NewPasswordPolicyHandlerWithPool creates a handler backed by a pgxpool.
func NewPasswordPolicyHandlerWithPool(pool *pgxpool.Pool) *PasswordPolicyHandler {
	return &PasswordPolicyHandler{pool: pool}
}

// passwordPolicyRow holds data from the password_policies table (new schema).
type passwordPolicyRow struct {
	ID                   string `json:"id"`
	Name                 string `json:"name"`
	MinLength            int    `json:"min_length"`
	MaxLength            int    `json:"max_length"`
	RequireUppercase     bool   `json:"require_uppercase"`
	RequireLowercase     bool   `json:"require_lowercase"`
	RequireDigits        bool   `json:"require_digits"`
	RequireSpecial       bool   `json:"require_special"`
	MinSpecialChars      int    `json:"min_special_chars"`
	PasswordHistoryCount int    `json:"password_history_count"`
	MaxAgeDays           int    `json:"max_age_days"`
	MinAgeDays           int    `json:"min_age_days"`
	LockoutAttempts      int    `json:"lockout_attempts"`
	LockoutDurationMins  int    `json:"lockout_duration_minutes"`
	IsActive             bool   `json:"is_active"`
}

// defaultPolicy returns the default policy when the DB is unavailable.
func defaultPolicy() passwordPolicyRow {
	return passwordPolicyRow{
		Name:                 "default",
		MinLength:            12,
		MaxLength:            128,
		RequireUppercase:     true,
		RequireLowercase:     true,
		RequireDigits:        true,
		RequireSpecial:       true,
		MinSpecialChars:      1,
		PasswordHistoryCount: 5,
		MaxAgeDays:           90,
		MinAgeDays:           1,
		LockoutAttempts:      5,
		LockoutDurationMins:  30,
		IsActive:             true,
	}
}

// Get returns the active password policy.
// GET /admin/password-policy
func (h *PasswordPolicyHandler) Get(c *gin.Context) {
	if h.pool != nil {
		ctx := c.Request.Context()
		var p passwordPolicyRow
		err := h.pool.QueryRow(ctx,
			`SELECT id, name, min_length, max_length, require_uppercase, require_lowercase,
			        require_digits, require_special, min_special_chars, password_history_count,
			        max_age_days, min_age_days, lockout_attempts, lockout_duration_minutes, is_active
			 FROM password_policies WHERE is_active = TRUE ORDER BY created_at LIMIT 1`,
		).Scan(
			&p.ID, &p.Name, &p.MinLength, &p.MaxLength, &p.RequireUppercase, &p.RequireLowercase,
			&p.RequireDigits, &p.RequireSpecial, &p.MinSpecialChars, &p.PasswordHistoryCount,
			&p.MaxAgeDays, &p.MinAgeDays, &p.LockoutAttempts, &p.LockoutDurationMins, &p.IsActive,
		)
		if err != nil {
			// ポリシー未設定なら既定値で正しいですが、読めなかっただけの場合に
			// 既定値を返すと、実際より緩い（あるいは厳しい）ポリシーが
			// 「現在の設定」として表示されます。
			ReadFailure(c, err, defaultPolicy())
			return
		}
		c.JSON(http.StatusOK, p)
		return
	}

	// Legacy store path
	if h.Store == nil {
		c.JSON(http.StatusOK, defaultPolicy())
		return
	}
	policy, err := h.Store.Get(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, policy)
}

// GetPolicy is an alias for Get (legacy router compatibility).
func (h *PasswordPolicyHandler) GetPolicy(c *gin.Context) {
	h.Get(c)
}

// Update replaces the active password policy.
// PUT /admin/password-policy
func (h *PasswordPolicyHandler) Update(c *gin.Context) {
	if h.pool != nil {
		var req passwordPolicyRow
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "無効なリクエストです: " + err.Error()})
			return
		}

		// Validate bounds
		if req.MinLength < 8 {
			req.MinLength = 8
		}
		if req.MinLength > 128 {
			req.MinLength = 128
		}
		if req.LockoutAttempts < 3 {
			req.LockoutAttempts = 3
		}
		if req.LockoutAttempts > 20 {
			req.LockoutAttempts = 20
		}
		if req.MaxAgeDays < 30 {
			req.MaxAgeDays = 30
		}
		if req.MaxAgeDays > 365 {
			req.MaxAgeDays = 365
		}

		ctx := c.Request.Context()
		_, err := h.pool.Exec(ctx,
			`UPDATE password_policies
			 SET min_length = $1, max_length = $2, require_uppercase = $3, require_lowercase = $4,
			     require_digits = $5, require_special = $6, min_special_chars = $7,
			     password_history_count = $8, max_age_days = $9, min_age_days = $10,
			     lockout_attempts = $11, lockout_duration_minutes = $12, updated_at = NOW()
			 WHERE is_active = TRUE`,
			req.MinLength, req.MaxLength, req.RequireUppercase, req.RequireLowercase,
			req.RequireDigits, req.RequireSpecial, req.MinSpecialChars,
			req.PasswordHistoryCount, req.MaxAgeDays, req.MinAgeDays,
			req.LockoutAttempts, req.LockoutDurationMins,
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
			return
		}

		// Log to audit_logs
		userID, _ := c.Get("user_id")
		userIDStr, _ := userID.(string)
		if _, err := h.pool.Exec(ctx,
			`INSERT INTO audit_logs (user_id, action, ip_address, status_code)
				 VALUES ($1, 'password_policy_update', $2, 200)`,
			userIDStr, c.ClientIP(),
		); !WriteOK(c, err) {
			return
		}

		h.Get(c)
		return
	}

	// Legacy store path
	var req store.PasswordPolicy
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "無効なリクエストです: " + err.Error()})
		return
	}

	if req.MinLength < 6 {
		req.MinLength = 6
	}
	if req.MinLength > 128 {
		req.MinLength = 128
	}
	if req.MaxAgeDays < 0 {
		req.MaxAgeDays = 0
	}
	if req.HistoryCount < 0 {
		req.HistoryCount = 0
	}

	if err := h.Store.Update(c.Request.Context(), req); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}

	updated, err := h.Store.Get(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"message": "パスワードポリシーを更新しました"})
		return
	}
	c.JSON(http.StatusOK, updated)
}

// UpdatePolicy is an alias for Update (legacy router compatibility).
func (h *PasswordPolicyHandler) UpdatePolicy(c *gin.Context) {
	h.Update(c)
}

// ValidatePassword validates a candidate password against the active policy.
// POST /admin/password-policy/validate or /auth/password-policy/validate
func (h *PasswordPolicyHandler) ValidatePassword(c *gin.Context) {
	var req struct {
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "password フィールドが必要です"})
		return
	}

	if h.pool != nil {
		ctx := c.Request.Context()
		var p passwordPolicyRow
		err := h.pool.QueryRow(ctx,
			`SELECT id, name, min_length, max_length, require_uppercase, require_lowercase,
			        require_digits, require_special, min_special_chars, password_history_count,
			        max_age_days, min_age_days, lockout_attempts, lockout_duration_minutes, is_active
			 FROM password_policies WHERE is_active = TRUE ORDER BY created_at LIMIT 1`,
		).Scan(
			&p.ID, &p.Name, &p.MinLength, &p.MaxLength, &p.RequireUppercase, &p.RequireLowercase,
			&p.RequireDigits, &p.RequireSpecial, &p.MinSpecialChars, &p.PasswordHistoryCount,
			&p.MaxAgeDays, &p.MinAgeDays, &p.LockoutAttempts, &p.LockoutDurationMins, &p.IsActive,
		)
		if err != nil {
			p = defaultPolicy()
		}

		violations := validatePasswordAgainstPolicy(req.Password, p)
		c.JSON(http.StatusOK, gin.H{
			"valid":      len(violations) == 0,
			"violations": violations,
		})
		return
	}

	// Legacy store path
	if h.Store == nil {
		c.JSON(http.StatusOK, gin.H{"valid": true, "violations": []string{}})
		return
	}

	policy, err := h.Store.Get(c.Request.Context())
	if err != nil {
		// ポリシーを読めないことは「違反なし」ではありません。
		// そのまま valid を返すと、規定を満たさないパスワードが通ります。
		ReadFailure(c, err, gin.H{"valid": true, "violations": []string{}})
		return
	}

	violations := h.Store.Violations(req.Password, policy)
	c.JSON(http.StatusOK, gin.H{
		"valid":      len(violations) == 0,
		"violations": violations,
	})
}

// GetHistory returns audit log of policy changes.
// GET /admin/password-policy/history
func (h *PasswordPolicyHandler) GetHistory(c *gin.Context) {
	if h.pool == nil {
		c.JSON(http.StatusOK, gin.H{"history": []interface{}{}, "total": 0})
		return
	}

	ctx := c.Request.Context()
	rows, err := h.pool.Query(ctx,
		`SELECT id, COALESCE(user_id, ''), action, COALESCE(ip_address, ''), timestamp::TEXT
		 FROM audit_logs
		 WHERE action = 'password_policy_update'
		 ORDER BY timestamp DESC
		 LIMIT 100`,
	)
	if err != nil {
		ReadFailure(c, err, gin.H{"history": []interface{}{}, "total": 0})
		return
	}
	defer rows.Close()

	type HistoryEntry struct {
		ID        string `json:"id"`
		UserID    string `json:"user_id"`
		Action    string `json:"action"`
		IPAddress string `json:"ip_address"`
		CreatedAt string `json:"created_at"`
	}

	var history []HistoryEntry
	for rows.Next() {
		var e HistoryEntry
		if err := rows.Scan(&e.ID, &e.UserID, &e.Action, &e.IPAddress, &e.CreatedAt); err == nil {
			history = append(history, e)
		}
	}
	if err := rows.Err(); err != nil {
		slog.Error("rows.Err: 結果の読み出しが途中で失敗しました", "error", err)
		ReadFailure(c, err, gin.H{"history": []interface{}{}, "total": 0})
		return
	}
	if history == nil {
		history = []HistoryEntry{}
	}

	c.JSON(http.StatusOK, gin.H{"history": history, "total": len(history)})
}

// validatePasswordAgainstPolicy checks a password against the pool-based policy.
func validatePasswordAgainstPolicy(password string, p passwordPolicyRow) []string {
	var violations []string

	if len(password) < p.MinLength {
		violations = append(violations,
			"パスワードは最低"+ppItoa(p.MinLength)+"文字必要です")
	}
	if p.MaxLength > 0 && len(password) > p.MaxLength {
		violations = append(violations,
			"パスワードは最大"+ppItoa(p.MaxLength)+"文字までです")
	}

	var hasUpper, hasLower, hasDigit bool
	specialCount := 0
	for _, r := range password {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			specialCount++
		}
	}

	if p.RequireUppercase && !hasUpper {
		violations = append(violations, "大文字（A-Z）を1文字以上含める必要があります")
	}
	if p.RequireLowercase && !hasLower {
		violations = append(violations, "小文字（a-z）を1文字以上含める必要があります")
	}
	if p.RequireDigits && !hasDigit {
		violations = append(violations, "数字（0-9）を1文字以上含める必要があります")
	}
	if p.RequireSpecial && specialCount < p.MinSpecialChars {
		violations = append(violations, "特殊文字を"+ppItoa(p.MinSpecialChars)+"文字以上含める必要があります")
	}

	return violations
}

// ppItoa converts an int to string for the password policy handler.
func ppItoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := false
	if i < 0 {
		neg = true
		i = -i
	}
	buf := make([]byte, 0, 10)
	for i > 0 {
		buf = append([]byte{byte('0' + i%10)}, buf...)
		i /= 10
	}
	if neg {
		buf = append([]byte{'-'}, buf...)
	}
	return string(buf)
}
