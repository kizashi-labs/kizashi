package auth

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// ─── RateLimiter.Middleware ────────────────────────────────────────────────────

func newTestRouter(rl *RateLimiter) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(rl.Middleware())
	r.GET("/login", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	return r
}

func TestMiddleware_AllowsRequestsWithinLimit(t *testing.T) {
	rl := &RateLimiter{entries: make(map[string]*windowEntry), limit: 2, window: time.Minute}
	r := newTestRouter(rl)

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/login", nil)
		req.RemoteAddr = "10.0.0.1:1234"
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("request %d: got status %d, want 200", i+1, w.Code)
		}
	}
}

func TestMiddleware_BlocksWithTooManyRequestsAfterLimit(t *testing.T) {
	rl := &RateLimiter{entries: make(map[string]*windowEntry), limit: 1, window: time.Minute}
	r := newTestRouter(rl)

	req1 := httptest.NewRequest(http.MethodGet, "/login", nil)
	req1.RemoteAddr = "10.0.0.2:1234"
	w1 := httptest.NewRecorder()
	r.ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("first request: got %d, want 200", w1.Code)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/login", nil)
	req2.RemoteAddr = "10.0.0.2:1234"
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	if w2.Code != http.StatusTooManyRequests {
		t.Errorf("second request over the limit: got %d, want 429", w2.Code)
	}
}

func TestMiddleware_DifferentIPsAreIndependentlyLimited(t *testing.T) {
	rl := &RateLimiter{entries: make(map[string]*windowEntry), limit: 1, window: time.Minute}
	r := newTestRouter(rl)

	reqA := httptest.NewRequest(http.MethodGet, "/login", nil)
	reqA.RemoteAddr = "10.0.0.3:1234"
	wA := httptest.NewRecorder()
	r.ServeHTTP(wA, reqA)

	reqB := httptest.NewRequest(http.MethodGet, "/login", nil)
	reqB.RemoteAddr = "10.0.0.4:1234"
	wB := httptest.NewRecorder()
	r.ServeHTTP(wB, reqB)

	if wA.Code != http.StatusOK || wB.Code != http.StatusOK {
		t.Errorf("different client IPs should each get their own limit: A=%d B=%d", wA.Code, wB.Code)
	}
}

func TestMiddleware_RateLimitDisabledFlag_BypassesLimiting(t *testing.T) {
	// DISABLE_LOGIN_RATE_LIMIT is intended ONLY for CI/E2E. Confirm the flag, when
	// set, truly bypasses the limiter even when the limit is exhausted.
	orig := rateLimitDisabled
	rateLimitDisabled = true
	defer func() { rateLimitDisabled = orig }()

	rl := &RateLimiter{entries: make(map[string]*windowEntry), limit: 1, window: time.Minute}
	r := newTestRouter(rl)

	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/login", nil)
		req.RemoteAddr = "10.0.0.5:1234"
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("request %d with rate limiting disabled: got %d, want 200", i+1, w.Code)
		}
	}
}

func TestMiddleware_BlockedResponse_HasJSONErrorBody(t *testing.T) {
	rl := &RateLimiter{entries: make(map[string]*windowEntry), limit: 1, window: time.Minute}
	r := newTestRouter(rl)

	req1 := httptest.NewRequest(http.MethodGet, "/login", nil)
	req1.RemoteAddr = "10.0.0.6:1234"
	r.ServeHTTP(httptest.NewRecorder(), req1)

	req2 := httptest.NewRequest(http.MethodGet, "/login", nil)
	req2.RemoteAddr = "10.0.0.6:1234"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req2)

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("got status %d, want 429", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct == "" {
		t.Error("429レスポンスにContent-Typeヘッダーが設定されるべきです")
	}
	if w.Body.Len() == 0 {
		t.Error("429レスポンスボディが空です")
	}
}

// ─── RateLimiter.Allow concurrency ──────────────────────────────────────────────

func TestRateLimiter_Allow_ConcurrentAccessDoesNotExceedLimit(t *testing.T) {
	// SECURITY: the limiter must not let concurrent requests race past the limit
	// (a race would defeat brute-force / credential-stuffing protection).
	rl := &RateLimiter{entries: make(map[string]*windowEntry), limit: 10, window: time.Minute}

	var wg sync.WaitGroup
	var mu sync.Mutex
	allowedCount := 0

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if rl.Allow("shared-client") {
				mu.Lock()
				allowedCount++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if allowedCount != 10 {
		t.Errorf("並行リクエスト下でも許可数は制限値と一致すべきです: got %d, want 10", allowedCount)
	}
}

// ─── TokenBlocklist concurrency ─────────────────────────────────────────────────

func TestBlocklist_ConcurrentRevokeAndCheck_NoRace(t *testing.T) {
	b := NewTokenBlocklist()
	var wg sync.WaitGroup

	for i := 0; i < 50; i++ {
		wg.Add(2)
		jti := "concurrent-jti"
		go func() {
			defer wg.Done()
			b.Revoke(jti, time.Now().Add(time.Hour))
		}()
		go func() {
			defer wg.Done()
			b.IsRevoked(jti)
		}()
	}
	wg.Wait()

	if !b.IsRevoked("concurrent-jti") {
		t.Error("並行アクセス後もRevoke済みJTIはIsRevoked=trueを返すべきです")
	}
}
