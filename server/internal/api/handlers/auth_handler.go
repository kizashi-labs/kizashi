package handlers

import (
	"context"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/edr-platform/server/internal/auth"
	"github.com/edr-platform/server/internal/metrics"
	"github.com/edr-platform/server/internal/store"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
)

// ─── Brute-force / rate-limit protection ──────────────────────

const (
	maxLoginAttempts = 5
	lockoutDuration  = 15 * time.Minute
)

type loginAttempt struct {
	count       int
	lockedUntil time.Time
}

type loginLimiter struct {
	mu       sync.Mutex
	attempts map[string]*loginAttempt
}

var globalLimiter = &loginLimiter{attempts: make(map[string]*loginAttempt)}

// loginRateLimitDisabled bypasses the brute-force lockout when set. Intended
// ONLY for E2E/CI where many login attempts (including intentional failures)
// originate from a single shared IP. Never enable in production.
var loginRateLimitDisabled = os.Getenv("DISABLE_LOGIN_RATE_LIMIT") == "true"

// allowed returns true if the IP is not locked out.
func (l *loginLimiter) allowed(ip string) bool {
	if loginRateLimitDisabled {
		return true
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	a, ok := l.attempts[ip]
	if !ok {
		return true
	}
	if !a.lockedUntil.IsZero() && time.Now().Before(a.lockedUntil) {
		return false
	}
	// Lockout expired — reset
	if !a.lockedUntil.IsZero() {
		delete(l.attempts, ip)
	}
	return true
}

func (l *loginLimiter) recordFailure(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	a, ok := l.attempts[ip]
	if !ok {
		a = &loginAttempt{}
		l.attempts[ip] = a
	}
	a.count++
	if a.count >= maxLoginAttempts {
		a.lockedUntil = time.Now().Add(lockoutDuration)
	}
}

func (l *loginLimiter) recordSuccess(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.attempts, ip)
}

// AuthHandler provides authentication endpoints.
type AuthHandler struct {
	JWTSecret string
	Users     *store.UserStore
	Blocklist *auth.TokenBlocklist  // required for server-side logout
	UserCache *auth.UserStatusCache // required for deactivation enforcement
	Sessions  *store.SessionStore   // optional: records login sessions
	Audit     *store.AuditStore     // optional: records login_failed (insider_threat_detector が読む語彙)

	// countUsers overrides how Login decides whether any DB user exists.
	// nil means "ask Users". テストから差し替えるためだけの口です —— この判定は
	// 「誤ったパスワードと管理者トークンの間に立っている唯一のもの」なので、
	// DB を要求する統合テスト（CI では回らない）ではなく、通常の go test で
	// 覆える形にしてあります。
	countUsers func(context.Context) (int, error)
}

// AuthClaims holds the JWT payload.
type AuthClaims struct {
	UserID   string `json:"user_id"`
	Role     string `json:"role"`
	TenantID string `json:"tenant_id"`
	jwt.RegisteredClaims
}

// NewAuthHandler creates a new AuthHandler.
func NewAuthHandler(jwtSecret string, users *store.UserStore) *AuthHandler {
	return &AuthHandler{JWTSecret: jwtSecret, Users: users}
}

// Login accepts email/password and returns a signed JWT.
// POST /api/v1/auth/login
func (h *AuthHandler) Login(c *gin.Context) {
	ip := c.ClientIP()

	if !globalLimiter.allowed(ip) {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "アカウントがロックされています。15分後に再試行してください"})
		return
	}

	var req struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "メールアドレスとパスワードが必要です"})
		return
	}

	// Normalize: accept both "username" and "email" fields
	email := req.Email
	if email == "" {
		email = req.Username
	}
	if email == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "メールアドレスが必要です"})
		return
	}

	// ─── Try DB-backed auth first ─────────────────────────────
	if h.Users != nil {
		user, err := h.Users.Authenticate(c.Request.Context(), email, req.Password)
		if err != nil && strings.HasPrefix(err.Error(), "アカウントがロックされています") {
			// DB-level lockout — return 429 same as IP-based lockout
			c.JSON(http.StatusTooManyRequests, gin.H{"error": err.Error()})
			return
		}
		if err == nil {
			globalLimiter.recordSuccess(ip)

			// If MFA is enabled, return a short-lived pre-auth token
			// instead of the full JWT. The client must complete MFA via /auth/mfa/verify.
			if user.MFAEnabled {
				preAuthToken, err := h.generatePreAuthToken(user.ID)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "トークンの生成に失敗しました"})
					return
				}
				// Fetch mfa_type so the frontend can display the correct MFA form.
				mfaType := "totp"
				if h.Users != nil {
					if t, err2 := h.Users.GetMFAType(c.Request.Context(), user.ID); err2 == nil {
						mfaType = t
					}
				}
				c.JSON(http.StatusOK, gin.H{
					"mfa_required":   true,
					"mfa_type":       mfaType,
					"pre_auth_token": preAuthToken,
					"user": gin.H{
						"id":    user.ID,
						"email": user.Email,
					},
				})
				return
			}

			tenantID := user.TenantID
			if tenantID == "" {
				tenantID = "00000000-0000-0000-0000-000000000001"
			}
			token, jti, err := h.generateToken(user.ID, user.Role, tenantID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "トークンの生成に失敗しました"})
				return
			}
			// Record session in DB.
			//
			// **「best-effort」と書いてありましたが、跡が残りません。**
			// この行はアクティブセッションの一覧と、管理者による強制
			// ログアウトの対象です —— 書けないと、**そのセッションは
			// 一覧に出ず、失効させることもできません。**
			// ログインそのものは成功しているので、応答は変えません。
			if h.Sessions != nil {
				if serr := h.Sessions.Create(c.Request.Context(), store.Session{
					UserID:     user.ID,
					JTI:        jti,
					IPAddress:  ip,
					DeviceInfo: map[string]interface{}{"user_agent": c.GetHeader("User-Agent")},
					CreatedAt:  time.Now(),
					LastSeenAt: time.Now(),
					ExpiresAt:  time.Now().Add(24 * time.Hour),
				}); serr != nil {
					metrics.BackgroundFailed("session_record", serr,
						"ログインセッションを記録できませんでした。一覧に出ず、強制ログアウトもできません",
						"user_id", user.ID)
				}
			}
			c.JSON(http.StatusOK, gin.H{
				"token":                token,
				"expires_in":           86400,
				"must_change_password": user.MustChangePassword,
				"user": gin.H{
					"id":                   user.ID,
					"email":                user.Email,
					"full_name":            user.FullName,
					"role":                 user.Role,
					"mfa_enabled":          user.MFAEnabled,
					"must_change_password": user.MustChangePassword,
				},
			})
			return
		}
	}

	// ─── Fallback: env-based admin account ────────────────────
	// Used for initial setup before DB users are created.
	//
	// **users に 1 行でもあれば、ここへは来ません。**
	//
	// 以前は DB 認証が失敗するたびにここへ落ちていました。この経路が発行する
	// トークンの user_id は UUID ではない文字列 "admin" なので、それを UUID 列へ
	// 書く操作は必ず 22P02 で失敗します。実際 system_updates.approved_by
	// (UUID REFERENCES users(id)) への書き込みが落ち、承認 API は
	// 「その更新は承認できる状態にない」という**別の理由**を返していました。
	// 検証環境の audit_logs には user_id='admin' の行が残っており、常用されて
	// いたことが分かっています。
	//
	// SeedAdminUser も「users が空のときだけ」シードするので、条件を揃えます。
	countUsers := h.countUsers
	if countUsers == nil && h.Users != nil {
		countUsers = h.Users.CountUsers
	}
	if countUsers != nil {
		n, err := countUsers(c.Request.Context())
		if err != nil {
			// 数えられないときは開けない。ここで開けると、DB が落ちている間だけ
			// env のパスワードで入れる口が生えます。
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "認証基盤を確認できません"})
			return
		}
		if n > 0 {
			globalLimiter.recordFailure(ip)
			h.auditLoginFailed(email, ip)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "メールアドレスまたはパスワードが正しくありません"})
			return
		}
	}

	adminPassword := os.Getenv("ADMIN_PASSWORD")
	if adminPassword == "" {
		adminPassword = "changeme"
	}
	// 本番環境ではデフォルトパスワードを拒否する
	weakAdminPasswords := []string{"changeme", "admin", "password", "admin123", "123456", "edrplatform"}
	for _, weak := range weakAdminPasswords {
		if strings.EqualFold(adminPassword, weak) {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error": "デフォルトの管理者パスワードが設定されています。ADMIN_PASSWORD 環境変数に強力なパスワードを設定してください。",
			})
			return
		}
	}
	if (email == "admin" || email == "admin@localhost" || email == "admin@example.com") && req.Password == adminPassword {
		globalLimiter.recordSuccess(ip)
		token, _, err := h.generateToken("admin", "admin", "00000000-0000-0000-0000-000000000001")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "トークンの生成に失敗しました"})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"token":      token,
			"expires_in": 86400,
			"user": gin.H{
				"id":    "admin",
				"email": "admin@localhost",
				"role":  "admin",
			},
		})
		return
	}

	globalLimiter.recordFailure(ip)
	h.auditLoginFailed(email, ip)
	c.JSON(http.StatusUnauthorized, gin.H{"error": "メールアドレスまたはパスワードが正しくありません"})
}

// auditLoginFailed records a semantic 'login_failed' audit row.
// insider_threat_detector が 15 分窓で数えて急増を検知する語彙。読み手と書き手の
// 対応は scheduler 側の契約テストが握っている。user_id には**入力された識別子**
// （メールアドレス）をそのまま入れる —— どのアカウントが叩かれているかが検知の単位。
func (h *AuthHandler) auditLoginFailed(email, ip string) {
	if h.Audit == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := h.Audit.Insert(ctx, &store.AuditLog{
			UserID:     email,
			Action:     "login_failed",
			IPAddress:  ip,
			StatusCode: http.StatusUnauthorized,
		}); err != nil {
			metrics.BackgroundFailed("audit_login_failed", err,
				"ログイン失敗の監査行を書けませんでした。総当たり検知の材料が欠けます")
		}
	}()
}

// Refresh issues a new token given a valid existing token.
// POST /api/v1/auth/refresh
func (h *AuthHandler) Refresh(c *gin.Context) {
	tokenStr := extractBearerTokenFromContext(c)
	if tokenStr == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "トークンが必要です"})
		return
	}

	claims, err := h.validateToken(tokenStr)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "無効なトークンです"})
		return
	}

	newToken, _, err := h.generateToken(claims.UserID, claims.Role, claims.TenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "トークンの更新に失敗しました"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token":      newToken,
		"expires_in": 86400,
	})
}

// Logout revokes the caller's JWT server-side so it can never be reused.
// POST /api/v1/auth/logout
func (h *AuthHandler) Logout(c *gin.Context) {
	if h.Blocklist != nil {
		tokenStr := extractBearerTokenFromContext(c)
		if tokenStr != "" {
			if claims, err := h.validateToken(tokenStr); err == nil && claims.ID != "" {
				expiry := time.Now().Add(24 * time.Hour) // default fallback
				if claims.ExpiresAt != nil {
					expiry = claims.ExpiresAt.Time
				}
				h.Blocklist.Revoke(claims.ID, expiry)
			}
		}
	}
	c.JSON(http.StatusOK, gin.H{"message": "ログアウトしました"})
}

// VerifyMFA completes the MFA step after login.
// Accepts a pre_auth_token (issued during Login when MFA is enabled)
// plus a 6-digit TOTP code or an 8-char backup code.
// POST /api/v1/auth/mfa/verify
func (h *AuthHandler) VerifyMFA(c *gin.Context) {
	var req struct {
		PreAuthToken string `json:"pre_auth_token" binding:"required"`
		Code         string `json:"code" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "pre_auth_token と code が必要です"})
		return
	}

	// Validate pre-auth token
	userID, _, err := h.validatePreAuthToken(req.PreAuthToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "無効または期限切れのトークンです"})
		return
	}

	if h.Users == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ユーザーストアが設定されていません"})
		return
	}

	// Fetch real user role for the full JWT
	user, err := h.Users.GetByID(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "ユーザーが見つかりません"})
		return
	}

	secret, _, err := h.Users.GetMFASecret(c.Request.Context(), userID)
	if err != nil || secret == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "MFAが設定されていません"})
		return
	}

	// Try TOTP first, then backup code
	var verified bool
	if len(req.Code) == 6 {
		verified = totp.Validate(req.Code, secret)
	}
	if !verified && len(req.Code) == 8 {
		// **error を捨てると、コードを消費できなかった回も通ります。**
		// `UseBackupCode` は使用済みの印を書けなければ false を返すように
		// なりましたが、その理由（DB に届かなかった）は error でしか
		// 分かりません —— 401 と 500 は、利用者にとって別の話です。
		ok, err := h.Users.UseBackupCode(c.Request.Context(), userID, req.Code)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
			return
		}
		verified = ok
	}

	if !verified {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "認証コードが正しくありません"})
		return
	}

	// Issue full JWT with real role from DB
	mfaTenantID := user.TenantID
	if mfaTenantID == "" {
		mfaTenantID = "00000000-0000-0000-0000-000000000001"
	}
	token, _, err := h.generateToken(userID, user.Role, mfaTenantID)
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

// SetupMFA generates a TOTP secret and returns the provisioning URI for QR code.
// POST /api/v1/auth/mfa/setup   (requires authentication)
func (h *AuthHandler) SetupMFA(c *gin.Context) {
	userID, _ := c.Get("user_id")
	userIDStr, _ := userID.(string)

	if h.Users == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ユーザーストアが設定されていません"})
		return
	}

	user, err := h.Users.GetByID(c.Request.Context(), userIDStr)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "ユーザーが見つかりません"})
		return
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "EDR Platform",
		AccountName: user.Email,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "MFAシークレットの生成に失敗しました"})
		return
	}

	// Generate backup codes
	backupCodes, err := store.GenerateBackupCodes(10)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "バックアップコードの生成に失敗しました"})
		return
	}

	// Persist secret + backup codes (MFA is not yet enabled — user must call /confirm)
	// We store the secret immediately so the client can verify the QR code works.
	// MFA is only marked enabled after a successful verify call.
	if err := h.Users.StoreMFASecret(c.Request.Context(), userIDStr, key.Secret()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "MFAシークレットの保存に失敗しました"})
		return
	}
	if err := h.Users.SaveBackupCodes(c.Request.Context(), userIDStr, backupCodes); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "バックアップコードの保存に失敗しました"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"secret":       key.Secret(),
		"otpauth_url":  key.URL(),
		"backup_codes": backupCodes,
		"message":      "認証アプリでQRコードをスキャンした後、コードを入力して /auth/mfa/confirm で確認してください",
	})
}

// ConfirmMFA verifies a TOTP code after setup to ensure the user's app is working,
// then marks MFA as enabled.
// POST /api/v1/auth/mfa/confirm
func (h *AuthHandler) ConfirmMFA(c *gin.Context) {
	userID, _ := c.Get("user_id")
	userIDStr, _ := userID.(string)

	var req struct {
		Code string `json:"code" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "code が必要です"})
		return
	}

	secret, _, err := h.Users.GetMFASecret(c.Request.Context(), userIDStr)
	if err != nil || secret == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "MFAのセットアップが完了していません。先に /auth/mfa/setup を呼び出してください"})
		return
	}

	if !totp.Validate(req.Code, secret) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "認証コードが正しくありません。認証アプリを確認してください"})
		return
	}

	if err := h.Users.EnableMFA(c.Request.Context(), userIDStr); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "MFAの有効化に失敗しました"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "MFAが有効化されました"})
}

// DisableMFA disables MFA for the authenticated user.
// POST /api/v1/auth/mfa/disable
func (h *AuthHandler) DisableMFA(c *gin.Context) {
	userID, _ := c.Get("user_id")
	userIDStr, _ := userID.(string)

	var req struct {
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "パスワードが必要です"})
		return
	}

	// Re-verify password before disabling MFA
	user, err := h.Users.GetByID(c.Request.Context(), userIDStr)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "ユーザーが見つかりません"})
		return
	}
	if _, authErr := h.Users.Authenticate(c.Request.Context(), user.Email, req.Password); authErr != nil { //nolint:govet
		c.JSON(http.StatusUnauthorized, gin.H{"error": "パスワードが正しくありません"})
		return
	}

	if err := h.Users.DisableMFA(c.Request.Context(), userIDStr); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "MFAの無効化に失敗しました"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "MFAを無効化しました"})
}

// GetBackupCodes returns the status of the user's MFA backup codes.
// Codes are bcrypt-hashed at rest, so they are shown masked here; plaintext is
// only ever returned once, by SetupMFA or RegenerateBackupCodes.
// GET /api/v1/auth/mfa/backup-codes
func (h *AuthHandler) GetBackupCodes(c *gin.Context) {
	userID, _ := c.Get("user_id")
	userIDStr, _ := userID.(string)

	statuses, err := h.Users.ListBackupCodeStatus(c.Request.Context(), userIDStr)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "バックアップコードの取得に失敗しました"})
		return
	}
	if len(statuses) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "backup codes not configured"})
		return
	}

	codes := make([]gin.H, 0, len(statuses))
	usageHistory := []gin.H{}
	generatedAt := statuses[0].CreatedAt
	for _, st := range statuses {
		if st.CreatedAt.Before(generatedAt) {
			generatedAt = st.CreatedAt
		}
		entry := gin.H{"code": "••••••••", "used": st.Used}
		if st.Used && st.UsedAt != nil {
			entry["used_at"] = st.UsedAt.UTC().Format(time.RFC3339)
			usageHistory = append(usageHistory, gin.H{"code": "••••••••", "used_at": st.UsedAt.UTC().Format(time.RFC3339)})
		}
		codes = append(codes, entry)
	}
	c.JSON(http.StatusOK, gin.H{
		"codes":         codes,
		"generated_at":  generatedAt.UTC().Format(time.RFC3339),
		"usage_history": usageHistory,
	})
}

// RegenerateBackupCodes replaces the user's backup codes and returns the new
// plaintext codes exactly once.
// POST /api/v1/auth/mfa/backup-codes/regenerate
func (h *AuthHandler) RegenerateBackupCodes(c *gin.Context) {
	userID, _ := c.Get("user_id")
	userIDStr, _ := userID.(string)

	user, err := h.Users.GetByID(c.Request.Context(), userIDStr)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "ユーザーが見つかりません"})
		return
	}
	if !user.MFAEnabled {
		c.JSON(http.StatusBadRequest, gin.H{"error": "MFAが有効になっていません。先にMFAを設定してください"})
		return
	}

	codes, err := store.GenerateBackupCodes(10)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "コードの生成に失敗しました"})
		return
	}
	if err := h.Users.SaveBackupCodes(c.Request.Context(), userIDStr, codes); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "コードの保存に失敗しました"})
		return
	}

	now := time.Now().UTC().Format(time.RFC3339)
	out := make([]gin.H, len(codes))
	for i, code := range codes {
		out[i] = gin.H{"code": code, "used": false}
	}
	c.JSON(http.StatusOK, gin.H{"codes": out, "generated_at": now, "usage_history": []gin.H{}})
}

// generateToken creates a signed HS256 JWT valid for 24 hours.
// Each token has a unique JTI (JWT ID) so individual tokens can be revoked.
// Returns (tokenString, jti, error).
func (h *AuthHandler) generateToken(userID, role, tenantID string) (string, string, error) {
	jti := uuid.New().String()
	claims := AuthClaims{
		UserID:   userID,
		Role:     role,
		TenantID: tenantID,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti, // JTI — enables server-side revocation
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "edr-platform",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(h.JWTSecret))
	return signed, jti, err
}

// generatePreAuthToken creates a short-lived (5 min) JWT used between
// the password step and the MFA step. It carries a "pre_auth" role so
// the middleware can reject it for all protected routes except /auth/mfa/verify.
func (h *AuthHandler) generatePreAuthToken(userID string) (string, error) {
	claims := AuthClaims{
		UserID: userID,
		Role:   "pre_auth",
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.New().String(),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "edr-platform",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(h.JWTSecret))
}

// validatePreAuthToken validates a pre-auth token and returns (userID, role, error).
func (h *AuthHandler) validatePreAuthToken(tokenStr string) (userID, role string, err error) {
	claims, err := h.validateToken(tokenStr)
	if err != nil {
		return "", "", err
	}
	if claims.Role != "pre_auth" {
		return "", "", jwt.ErrTokenInvalidClaims
	}
	// Role stored in pre-auth token is "pre_auth"; we need the real role.
	// Fetch from DB via UserStore — the real role is in the users table.
	// For simplicity we return "analyst" as default; the full JWT generation
	// will fetch the correct role from the DB during the verify step.
	return claims.UserID, "analyst", nil
}

// validateToken parses and validates a JWT, returning its claims.
func (h *AuthHandler) validateToken(tokenStr string) (*AuthClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &AuthClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return []byte(h.JWTSecret), nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*AuthClaims)
	if !ok || !token.Valid {
		return nil, jwt.ErrTokenInvalidClaims
	}
	return claims, nil
}

// extractBearerTokenFromContext reads the Authorization header.
func extractBearerTokenFromContext(c *gin.Context) string {
	header := c.GetHeader("Authorization")
	if len(header) > 7 && header[:7] == "Bearer " {
		return header[7:]
	}
	return ""
}
