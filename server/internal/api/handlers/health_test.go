package handlers_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/edr-platform/server/internal/api/handlers"
)

// TestHealthHandlerLive tests the liveness probe endpoint.
// No DB pool is needed for the Live handler.
func TestHealthHandlerLive(t *testing.T) {
	gin.SetMode(gin.TestMode)

	h := handlers.NewHealthHandler(nil, "test-1.0.0")
	r := gin.New()
	r.GET("/healthz", h.Live)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var body map[string]string
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body["status"] != "alive" {
		t.Errorf("expected status=alive, got %q", body["status"])
	}
	if body["time"] == "" {
		t.Error("response should include a time field")
	}
}

// TestHealthHandlerLive_Version verifies the handler can be created with a version string.
func TestHealthHandlerLive_Version(t *testing.T) {
	gin.SetMode(gin.TestMode)

	versions := []string{"1.0.0", "v2.3.1-beta", ""}
	for _, ver := range versions {
		t.Run("version="+ver, func(t *testing.T) {
			h := handlers.NewHealthHandler(nil, ver)
			r := gin.New()
			r.GET("/healthz", h.Live)

			req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("expected 200, got %d", w.Code)
			}
		})
	}
}

// TestHealthHandlerLive_Method verifies that non-GET methods receive 404 or 405.
// Gin returns 404 by default for unregistered methods; 405 requires
// HandleMethodNotAllowed=true on the engine. Either response is acceptable.
func TestHealthHandlerLive_Method(t *testing.T) {
	gin.SetMode(gin.TestMode)

	h := handlers.NewHealthHandler(nil, "test-1.0.0")

	// Engine with method-not-allowed enabled.
	r := gin.New()
	r.HandleMethodNotAllowed = true
	r.GET("/healthz", h.Live)

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/healthz", nil)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if w.Code != http.StatusMethodNotAllowed {
				t.Errorf("method %s: expected 405, got %d", method, w.Code)
			}
		})
	}
}

// TestHealthHandlerReady_NilPool verifies that Ready panics or returns 503
// when the pool is nil. Since the production handler calls pool.Ping which
// would panic on nil, this test only exercises the Live endpoint (which does
// not touch the pool). The Ready endpoint integration is covered by
// integration_test.go with a real DB.
func TestHealthHandlerReady_NoPool(t *testing.T) {
	// This test explicitly only validates that Live works without a pool.
	// Ready with a nil pool would panic — that's intentional in production
	// (you should always have a pool). We document this expectation here.
	gin.SetMode(gin.TestMode)

	h := handlers.NewHealthHandler(nil, "v0")
	r := gin.New()
	r.GET("/healthz", h.Live)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Live without pool: expected 200, got %d", w.Code)
	}
}

// BenchmarkHealthHandlerLive measures the in-process handler performance.
func BenchmarkHealthHandlerLive(b *testing.B) {
	gin.SetMode(gin.TestMode)

	h := handlers.NewHealthHandler(nil, "bench-1.0.0")
	r := gin.New()
	r.GET("/healthz", h.Live)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
	}
}
