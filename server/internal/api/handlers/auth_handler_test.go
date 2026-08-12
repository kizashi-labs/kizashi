package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// ─── loginLimiter tests ──────────────────────────────────────────────────────

func TestLoginLimiter_AllowsFirstRequest(t *testing.T) {
	l := &loginLimiter{attempts: make(map[string]*loginAttempt)}
	if !l.allowed("1.2.3.4") {
		t.Fatal("新規IPは許可されるべきです")
	}
}

func TestLoginLimiter_LocksAfterMaxFailures(t *testing.T) {
	l := &loginLimiter{attempts: make(map[string]*loginAttempt)}
	ip := "5.6.7.8"
	for i := 0; i < maxLoginAttempts; i++ {
		l.recordFailure(ip)
	}
	if l.allowed(ip) {
		t.Fatalf("%d回失敗後はロックされるべきです", maxLoginAttempts)
	}
}

func TestLoginLimiter_UnlocksAfterDuration(t *testing.T) {
	l := &loginLimiter{attempts: make(map[string]*loginAttempt)}
	ip := "9.10.11.12"
	for i := 0; i < maxLoginAttempts; i++ {
		l.recordFailure(ip)
	}
	// 手動でロックを過去に設定
	l.mu.Lock()
	l.attempts[ip].lockedUntil = time.Now().Add(-1 * time.Second)
	l.mu.Unlock()

	if !l.allowed(ip) {
		t.Fatal("ロック期限切れ後は許可されるべきです")
	}
}

func TestLoginLimiter_RecordSuccessResetsAttempts(t *testing.T) {
	l := &loginLimiter{attempts: make(map[string]*loginAttempt)}
	ip := "13.14.15.16"
	for i := 0; i < maxLoginAttempts-1; i++ {
		l.recordFailure(ip)
	}
	l.recordSuccess(ip)
	if !l.allowed(ip) {
		t.Fatal("成功後はリセットされ許可されるべきです")
	}
}

// ─── AuthHandler.Login tests ─────────────────────────────────────────────────

func newTestAuthHandler() *AuthHandler {
	return &AuthHandler{
		JWTSecret: "test-secret-32-bytes-long-enough!",
		Users:     nil, // DB不要のテストのみ
	}
}

func newTestRouter(h *AuthHandler) *gin.Engine {
	r := gin.New()
	r.POST("/login", h.Login)
	return r
}

func TestLogin_MissingPassword(t *testing.T) {
	h := newTestAuthHandler()
	r := newTestRouter(h)

	body, _ := json.Marshal(map[string]string{"username": "admin"})
	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("パスワード未指定は400を期待、got %d", w.Code)
	}
}

func TestLogin_EmptyEmail(t *testing.T) {
	h := newTestAuthHandler()
	r := newTestRouter(h)

	body, _ := json.Marshal(map[string]string{"password": "pass"})
	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("メール未指定は400を期待、got %d", w.Code)
	}
}

func TestLogin_WrongAdminPassword(t *testing.T) {
	t.Setenv("ADMIN_PASSWORD", "Test@Strong#Pass1!")
	h := newTestAuthHandler()
	r := newTestRouter(h)

	body, _ := json.Marshal(map[string]string{
		"username": "admin",
		"password": "wrongpassword",
	})
	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("誤パスワードは401を期待、got %d", w.Code)
	}
}

func TestLogin_RateLimitAfterMaxFailures(t *testing.T) {
	t.Setenv("ADMIN_PASSWORD", "Test@Strong#Pass1!")
	// グローバルlimiterをリセット
	globalLimiter = &loginLimiter{attempts: make(map[string]*loginAttempt)}

	h := newTestAuthHandler()
	r := newTestRouter(h)

	body, _ := json.Marshal(map[string]string{
		"username": "admin",
		"password": "wrongpass",
	})

	for i := 0; i < maxLoginAttempts; i++ {
		req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-For", "192.0.2.1")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
	}

	// maxLoginAttempts+1回目はレート制限
	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", "192.0.2.1")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("レート制限後は429を期待、got %d", w.Code)
	}

	// テスト後にリセット
	globalLimiter = &loginLimiter{attempts: make(map[string]*loginAttempt)}
}

// ─── Token generation/validation tests ──────────────────────────────────────

func TestGenerateAndValidateToken(t *testing.T) {
	h := newTestAuthHandler()

	token, _, err := h.generateToken("user-123", "analyst", "00000000-0000-0000-0000-000000000001")
	if err != nil {
		t.Fatalf("トークン生成失敗: %v", err)
	}
	if token == "" {
		t.Fatal("トークンが空")
	}

	claims, err := h.validateToken(token)
	if err != nil {
		t.Fatalf("トークン検証失敗: %v", err)
	}
	if claims.UserID != "user-123" {
		t.Fatalf("UserID不一致: got %q, want %q", claims.UserID, "user-123")
	}
	if claims.Role != "analyst" {
		t.Fatalf("Role不一致: got %q, want %q", claims.Role, "analyst")
	}
}

func TestValidateToken_InvalidSignature(t *testing.T) {
	h := newTestAuthHandler()
	h2 := &AuthHandler{JWTSecret: "different-secret-32-bytes-long!!!"}

	token, _, _ := h.generateToken("user-123", "analyst", "00000000-0000-0000-0000-000000000001")
	_, err := h2.validateToken(token)
	if err == nil {
		t.Fatal("異なるシークレットのトークンは拒否されるべきです")
	}
}

func TestGeneratePreAuthToken_Role(t *testing.T) {
	h := newTestAuthHandler()

	token, err := h.generatePreAuthToken("user-456")
	if err != nil {
		t.Fatalf("pre-authトークン生成失敗: %v", err)
	}

	claims, err := h.validateToken(token)
	if err != nil {
		t.Fatalf("pre-authトークン検証失敗: %v", err)
	}
	if claims.Role != "pre_auth" {
		t.Fatalf("pre-authトークンのroleは'pre_auth'のはず、got %q", claims.Role)
	}
	if claims.UserID != "user-456" {
		t.Fatalf("UserID不一致: got %q, want %q", claims.UserID, "user-456")
	}
}

func TestValidatePreAuthToken_RejectsFullToken(t *testing.T) {
	h := newTestAuthHandler()
	// 通常トークンはpre-auth検証で拒否される
	token, _, _ := h.generateToken("user-789", "analyst", "00000000-0000-0000-0000-000000000001")
	_, _, err := h.validatePreAuthToken(token)
	if err == nil {
		t.Fatal("通常のJWTはpre-auth検証で拒否されるべきです")
	}
}

func TestExtractBearerToken(t *testing.T) {
	tests := []struct {
		header string
		want   string
	}{
		{"Bearer abc123", "abc123"},
		{"bearer abc123", ""}, // case-sensitive
		{"abc123", ""},
		{"", ""},
		{"Bearer ", ""},
	}

	for _, tt := range tests {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
		c.Request.Header.Set("Authorization", tt.header)
		got := extractBearerTokenFromContext(c)
		if got != tt.want {
			t.Errorf("header=%q: got %q, want %q", tt.header, got, tt.want)
		}
	}
}
