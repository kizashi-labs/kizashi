package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/edr-platform/server/internal/api/handlers"
)

// ─── PAMHandler ───────────────────────────────────────────────────────────────

// TestPAMHandler_ListRequests_NoTable verifies that ListRequests returns 200
// with an empty array when the pam_access_requests table does not exist.
func TestPAMHandler_ListRequests_NoTable(t *testing.T) {
	gin.SetMode(gin.TestMode)
	pool := testPool(t)

	h := handlers.NewPAMHandler(pool)
	r := gin.New()
	r.GET("/pam/requests", h.ListRequests)

	req := httptest.NewRequest(http.MethodGet, "/pam/requests", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if _, ok := resp["requests"]; !ok {
		t.Error("response body should contain a 'requests' key")
	}
}

// TestPAMHandler_CreateRequest_MissingJustification verifies that CreateRequest
// returns 400 when "justification" is absent.
func TestPAMHandler_CreateRequest_MissingJustification(t *testing.T) {
	gin.SetMode(gin.TestMode)
	pool := testPool(t)

	h := handlers.NewPAMHandler(pool)
	r := gin.New()
	r.POST("/pam/requests", h.CreateRequest)

	body := map[string]interface{}{
		"target_resource":  "prod-db-01",
		"resource_type":    "database",
		"access_level":     "read",
		"duration_minutes": 30,
		// justification intentionally omitted
	}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/pam/requests", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// Expects 400 (validation) or 503 (table not available).
	if w.Code == http.StatusCreated || w.Code == http.StatusOK {
		t.Errorf("expected non-2xx for missing justification, got %d: %s", w.Code, w.Body.String())
	}
}

// TestPAMHandler_CreateRequest_DurationTooLow verifies that duration_minutes=0
// is rejected with a 400.
func TestPAMHandler_CreateRequest_DurationTooLow(t *testing.T) {
	gin.SetMode(gin.TestMode)
	pool := testPool(t)

	h := handlers.NewPAMHandler(pool)
	r := gin.New()
	r.POST("/pam/requests", h.CreateRequest)

	body := map[string]interface{}{
		"target_resource":  "bastion-01",
		"justification":    "emergency maintenance",
		"duration_minutes": 0, // invalid: must be >= 1
	}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/pam/requests", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code == http.StatusCreated || w.Code == http.StatusOK {
		t.Errorf("expected non-2xx for duration_minutes=0, got %d: %s", w.Code, w.Body.String())
	}
}

// TestPAMHandler_CreateRequest_DurationTooHigh verifies that duration_minutes
// exceeding the 480-minute maximum is rejected.
func TestPAMHandler_CreateRequest_DurationTooHigh(t *testing.T) {
	gin.SetMode(gin.TestMode)
	pool := testPool(t)

	h := handlers.NewPAMHandler(pool)
	r := gin.New()
	r.POST("/pam/requests", h.CreateRequest)

	body := map[string]interface{}{
		"target_resource":  "bastion-01",
		"justification":    "long access needed",
		"duration_minutes": 999, // exceeds max of 480
	}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/pam/requests", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code == http.StatusCreated || w.Code == http.StatusOK {
		t.Errorf("expected non-2xx for duration_minutes=999, got %d: %s", w.Code, w.Body.String())
	}
}

// TestPAMHandler_ListSessions_NoTable verifies that ListSessions returns 200
// with an empty sessions array when the pam_sessions table does not exist.
func TestPAMHandler_ListSessions_NoTable(t *testing.T) {
	gin.SetMode(gin.TestMode)
	pool := testPool(t)

	h := handlers.NewPAMHandler(pool)
	r := gin.New()
	r.GET("/pam/sessions", h.ListSessions)

	req := httptest.NewRequest(http.MethodGet, "/pam/sessions", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if _, ok := resp["sessions"]; !ok {
		t.Error("response body should contain a 'sessions' key")
	}
}

// TestPAMHandler_GetStats_ReturnsJSON verifies that GetStats always returns
// 200 with a JSON object regardless of whether the tables exist.
func TestPAMHandler_GetStats_ReturnsJSON(t *testing.T) {
	gin.SetMode(gin.TestMode)
	pool := testPool(t)

	h := handlers.NewPAMHandler(pool)
	r := gin.New()
	r.GET("/pam/stats", h.GetStats)

	req := httptest.NewRequest(http.MethodGet, "/pam/stats", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("GetStats response is not valid JSON: %v", err)
	}
}

// TestPAMHandler_MethodNotAllowed verifies that PUT to /pam/requests returns 405
// when the router has HandleMethodNotAllowed enabled.
func TestPAMHandler_MethodNotAllowed(t *testing.T) {
	gin.SetMode(gin.TestMode)
	pool := testPool(t)

	h := handlers.NewPAMHandler(pool)
	r := gin.New()
	r.HandleMethodNotAllowed = true
	r.GET("/pam/requests", h.ListRequests)
	r.POST("/pam/requests", h.CreateRequest)

	req := httptest.NewRequest(http.MethodPut, "/pam/requests", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// TestPAMHandler_GetRequest_NotFound verifies that fetching a non-existent
// request ID when the table doesn't exist returns a non-2xx status.
func TestPAMHandler_GetRequest_NotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)
	pool := testPool(t)

	h := handlers.NewPAMHandler(pool)
	r := gin.New()
	r.GET("/pam/requests/:id", h.GetRequest)

	req := httptest.NewRequest(http.MethodGet, "/pam/requests/00000000-0000-0000-0000-000000000000", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// Either 404 (table exists, row not found) or 404 (table doesn't exist).
	if w.Code == http.StatusOK {
		t.Errorf("expected non-200 for missing request ID, got 200: %s", w.Body.String())
	}
}
