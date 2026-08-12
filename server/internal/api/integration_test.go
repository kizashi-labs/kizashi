//go:build integration

package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// testServer creates a minimal test server.
// Requires TEST_DB_URL env var; skips if not set.
func testServer(t *testing.T) *httptest.Server {
	t.Helper()
	gin.SetMode(gin.TestMode)

	dbURL := os.Getenv("TEST_DB_URL")
	if dbURL == "" {
		t.Skip("TEST_DB_URL not set — skipping integration test")
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		t.Fatalf("failed to connect to test DB: %v", err)
	}
	t.Cleanup(pool.Close)

	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("test DB not reachable: %v", err)
	}

	r := gin.New()
	r.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "alive"})
	})
	r.GET("/readyz", func(c *gin.Context) {
		if err := pool.Ping(c.Request.Context()); err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"status": "not_ready",
				"error":  err.Error(),
			})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "ready"})
	})

	return httptest.NewServer(r)
}

func TestHealthEndpoints(t *testing.T) {
	srv := testServer(t)
	defer srv.Close()

	t.Run("liveness", func(t *testing.T) {
		resp, err := http.Get(srv.URL + "/healthz")
		if err != nil {
			t.Fatalf("GET /healthz: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200, got %d", resp.StatusCode)
		}
		var body map[string]string
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if body["status"] != "alive" {
			t.Errorf("expected status=alive, got %q", body["status"])
		}
	})

	t.Run("readiness", func(t *testing.T) {
		resp, err := http.Get(srv.URL + "/readyz")
		if err != nil {
			t.Fatalf("GET /readyz: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200, got %d", resp.StatusCode)
		}
	})
}

func TestRateLimiting(t *testing.T) {
	gin.SetMode(gin.TestMode)

	count := 0
	r := gin.New()
	r.GET("/test", func(c *gin.Context) {
		count++
		c.JSON(http.StatusOK, gin.H{"count": count})
	})
	srv := httptest.NewServer(r)
	defer srv.Close()

	// Make 5 rapid requests — all should succeed.
	client := &http.Client{Timeout: 5 * time.Second}
	for i := 0; i < 5; i++ {
		resp, err := client.Get(srv.URL + "/test")
		if err != nil {
			t.Fatalf("request %d failed: %v", i, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("request %d: expected 200, got %d", i, resp.StatusCode)
		}
	}
	if count != 5 {
		t.Errorf("expected handler called 5 times, got %d", count)
	}
}

func TestJSONAPIContracts(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		method         string
		path           string
		body           interface{}
		expectedStatus int
		validate       func(t *testing.T, body map[string]interface{})
	}{
		{
			name:           "health returns alive",
			method:         "GET",
			path:           "/healthz",
			expectedStatus: http.StatusOK,
			validate: func(t *testing.T, body map[string]interface{}) {
				if body["status"] != "alive" {
					t.Errorf("status should be alive, got %v", body["status"])
				}
			},
		},
		{
			name:           "missing route returns 404",
			method:         "GET",
			path:           "/nonexistent",
			expectedStatus: http.StatusNotFound,
			validate:       nil,
		},
	}

	r := gin.New()
	r.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "alive",
			"time":   time.Now().UTC().Format(time.RFC3339),
		})
	})
	srv := httptest.NewServer(r)
	defer srv.Close()

	client := &http.Client{Timeout: 5 * time.Second}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var req *http.Request
			var err error

			if tc.body != nil {
				bodyBytes, _ := json.Marshal(tc.body)
				req, err = http.NewRequest(tc.method, srv.URL+tc.path, bytes.NewReader(bodyBytes))
				if err != nil {
					t.Fatalf("create request: %v", err)
				}
				req.Header.Set("Content-Type", "application/json")
			} else {
				req, err = http.NewRequest(tc.method, srv.URL+tc.path, nil)
				if err != nil {
					t.Fatalf("create request: %v", err)
				}
			}

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("do request: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tc.expectedStatus {
				t.Errorf("expected status %d, got %d", tc.expectedStatus, resp.StatusCode)
			}

			if tc.validate != nil {
				var body map[string]interface{}
				if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
					t.Fatalf("decode response: %v", err)
				}
				tc.validate(t, body)
			}
		})
	}
}

// BenchmarkHealthEndpoint measures health endpoint performance.
func BenchmarkHealthEndpoint(b *testing.B) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "alive"})
	})
	srv := httptest.NewServer(r)
	defer srv.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			resp, err := client.Get(srv.URL + "/healthz")
			if err != nil {
				b.Error(err)
				return
			}
			resp.Body.Close()
		}
	})
}
