package middleware

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// newTestRouter は gin.New() + ミドルウェア + テスト用ハンドラをセットアップする。
func newTestRouter(mw gin.HandlerFunc, status int, body string) *gin.Engine {
	r := gin.New()
	r.Use(mw)
	r.GET("/test", func(c *gin.Context) {
		c.String(status, body)
	})
	r.POST("/test", func(c *gin.Context) {
		c.String(status, body)
	})
	return r
}

// ─── SecurityHeaders ──────────────────────────────────────────────────────────

func TestSecurityHeaders_Present(t *testing.T) {
	r := newTestRouter(SecurityHeaders(), http.StatusOK, "ok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	r.ServeHTTP(w, req)

	cases := []struct {
		header string
		want   string
	}{
		{"X-Content-Type-Options", "nosniff"},
		{"X-Frame-Options", "DENY"},
		{"X-XSS-Protection", "1; mode=block"},
		{"Referrer-Policy", "strict-origin-when-cross-origin"},
	}
	for _, tc := range cases {
		if got := w.Header().Get(tc.header); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.header, got, tc.want)
		}
	}
}

func TestSecurityHeaders_NoCacheControlOnGET(t *testing.T) {
	r := newTestRouter(SecurityHeaders(), http.StatusOK, "ok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	r.ServeHTTP(w, req)
	// GETリクエストにはCache-Controlをセットしない
	if cc := w.Header().Get("Cache-Control"); cc == "no-store" {
		t.Error("GET リクエストに Cache-Control: no-store がセットされるべきでない")
	}
}

func TestSecurityHeaders_NoCacheOnPOST(t *testing.T) {
	r := newTestRouter(SecurityHeaders(), http.StatusOK, "ok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	r.ServeHTTP(w, req)
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("POST: Cache-Control: got %q, want %q", got, "no-store")
	}
}

func TestSecurityHeaders_ServerHeaderEmpty(t *testing.T) {
	r := newTestRouter(SecurityHeaders(), http.StatusOK, "ok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	r.ServeHTTP(w, req)
	if got := w.Header().Get("Server"); got != "" {
		t.Errorf("Server header should be empty for fingerprinting prevention, got %q", got)
	}
}

// ─── RequestID ───────────────────────────────────────────────────────────────

func TestRequestID_GeneratesWhenMissing(t *testing.T) {
	r := newTestRouter(RequestID(), http.StatusOK, "ok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	r.ServeHTTP(w, req)

	id := w.Header().Get(RequestIDHeader)
	if id == "" {
		t.Error("X-Request-ID ヘッダが空です")
	}
	// UUID形式 (36文字) であること
	if len(id) != 36 {
		t.Errorf("X-Request-ID の長さ: got %d, want 36", len(id))
	}
}

func TestRequestID_PreservesExistingID(t *testing.T) {
	r := newTestRouter(RequestID(), http.StatusOK, "ok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set(RequestIDHeader, "my-custom-request-id")
	r.ServeHTTP(w, req)

	if got := w.Header().Get(RequestIDHeader); got != "my-custom-request-id" {
		t.Errorf("既存の Request-ID を変更してはならない: got %q", got)
	}
}

func TestRequestID_UniquePerRequest(t *testing.T) {
	r := newTestRouter(RequestID(), http.StatusOK, "ok")
	ids := make(map[string]bool)
	for i := 0; i < 10; i++ {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		r.ServeHTTP(w, req)
		id := w.Header().Get(RequestIDHeader)
		if ids[id] {
			t.Errorf("重複した Request-ID: %q", id)
		}
		ids[id] = true
	}
}

// ─── tokenBucket (RateLimit内部) ─────────────────────────────────────────────

func TestTokenBucket_AllowsUpToBurst(t *testing.T) {
	b := newTokenBucket(3, 0) // burst=3、補充なし
	for i := 0; i < 3; i++ {
		if !b.allow() {
			t.Errorf("リクエスト %d は許可されるべきです", i+1)
		}
	}
}

func TestTokenBucket_BlocksAfterBurst(t *testing.T) {
	b := newTokenBucket(2, 0) // burst=2、補充なし
	b.allow()
	b.allow()
	if b.allow() {
		t.Error("バースト超過後は拒否されるべきです")
	}
}

func TestTokenBucket_RefillsOverTime(t *testing.T) {
	b := newTokenBucket(1, 100) // burst=1、100トークン/秒
	b.allow()                   // バケットを空にする
	// 補充のため少し待つ
	time.Sleep(20 * time.Millisecond)
	if !b.allow() {
		t.Error("時間経過後は補充されて許可されるべきです")
	}
}

func TestRateLimit_Returns429WhenExceeded(t *testing.T) {
	// burst=1 なので2リクエスト目は弾かれる
	r := newTestRouter(RateLimit(1, 0), http.StatusOK, "ok")

	w1 := httptest.NewRecorder()
	r.ServeHTTP(w1, httptest.NewRequest(http.MethodGet, "/test", nil))

	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, httptest.NewRequest(http.MethodGet, "/test", nil))

	if w2.Code != http.StatusTooManyRequests {
		t.Errorf("429を期待: got %d", w2.Code)
	}
}

func TestRateLimit_RetryAfterHeader(t *testing.T) {
	r := newTestRouter(RateLimit(1, 0), http.StatusOK, "ok")
	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/test", nil))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/test", nil))
	if w.Header().Get("Retry-After") == "" {
		t.Error("Retry-After ヘッダがセットされていません")
	}
}

func TestRateLimit_SeparateBucketsPerIP(t *testing.T) {
	// IPが異なれば別々のバケット
	r := newTestRouter(RateLimit(1, 0), http.StatusOK, "ok")

	req1 := httptest.NewRequest(http.MethodGet, "/test", nil)
	req1.RemoteAddr = "192.168.1.1:1234"
	w1 := httptest.NewRecorder()
	r.ServeHTTP(w1, req1)

	req2 := httptest.NewRequest(http.MethodGet, "/test", nil)
	req2.RemoteAddr = "192.168.1.2:1234"
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)

	if w1.Code != http.StatusOK {
		t.Errorf("IP1 first request: got %d, want 200", w1.Code)
	}
	if w2.Code != http.StatusOK {
		t.Errorf("IP2 first request: got %d, want 200", w2.Code)
	}
}

func TestRateLimit_ConcurrentSafe(t *testing.T) {
	r := newTestRouter(RateLimit(100, 100), http.StatusOK, "ok")
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			r.ServeHTTP(w, req)
		}()
	}
	wg.Wait() // panic やデッドロックがなければOK
}

// ─── CacheMiddleware ──────────────────────────────────────────────────────────

func TestCacheMiddleware_MissOnFirstRequest(t *testing.T) {
	// グローバルキャッシュをリセット
	globalCache.mu.Lock()
	globalCache.entries = make(map[string]*cacheEntry)
	globalCache.hits = 0
	globalCache.misses = 0
	globalCache.mu.Unlock()

	r := newTestRouter(CacheMiddleware(1*time.Minute), http.StatusOK, "cached-body")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	r.ServeHTTP(w, req)

	if got := w.Header().Get("X-Cache"); got != "MISS" {
		t.Errorf("初回リクエスト X-Cache: got %q, want MISS", got)
	}
}

func TestCacheMiddleware_HitOnSecondRequest(t *testing.T) {
	globalCache.mu.Lock()
	globalCache.entries = make(map[string]*cacheEntry)
	globalCache.hits = 0
	globalCache.misses = 0
	globalCache.mu.Unlock()

	r := newTestRouter(CacheMiddleware(1*time.Minute), http.StatusOK, "cached-body")

	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/test", nil))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/test", nil))

	if got := w.Header().Get("X-Cache"); got != "HIT" {
		t.Errorf("2回目リクエスト X-Cache: got %q, want HIT", got)
	}
}

func TestCacheMiddleware_SkipsPOST(t *testing.T) {
	globalCache.mu.Lock()
	globalCache.entries = make(map[string]*cacheEntry)
	globalCache.mu.Unlock()

	r := newTestRouter(CacheMiddleware(1*time.Minute), http.StatusOK, "ok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	r.ServeHTTP(w, req)

	// POSTはキャッシュしないので X-Cache ヘッダなし
	if got := w.Header().Get("X-Cache"); got != "" {
		t.Errorf("POST はキャッシュされるべきでない: X-Cache=%q", got)
	}
}

func TestCacheMiddleware_ExpiredEntryIsRefreshed(t *testing.T) {
	globalCache.mu.Lock()
	globalCache.entries = make(map[string]*cacheEntry)
	globalCache.hits = 0
	globalCache.misses = 0
	globalCache.mu.Unlock()

	// TTL 1ms — すぐ期限切れ
	r := newTestRouter(CacheMiddleware(1*time.Millisecond), http.StatusOK, "ok")
	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/test", nil))
	time.Sleep(5 * time.Millisecond)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/test", nil))
	// 期限切れなので再びMISS
	if got := w.Header().Get("X-Cache"); got != "MISS" {
		t.Errorf("TTL期限切れ後は MISS になるべき: got %q", got)
	}
}

func TestMinFloat(t *testing.T) {
	cases := []struct {
		a, b float64
		want float64
	}{
		{1.0, 2.0, 1.0},
		{5.0, 3.0, 3.0},
		{0.0, 0.0, 0.0},
		{-1.0, 1.0, -1.0},
	}
	for _, tc := range cases {
		if got := minFloat(tc.a, tc.b); got != tc.want {
			t.Errorf("minFloat(%v, %v) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}
