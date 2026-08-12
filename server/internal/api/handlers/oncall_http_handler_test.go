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

// ─── OnCallHandler – HTTP integration tests ──────────────────────────────────

// TestOnCallHandler_ListIntegrations_ReturnsJSON verifies that ListIntegrations
// returns 200 with an "integrations" key. The handler auto-creates the tables
// (CREATE TABLE IF NOT EXISTS) on every call, so this is safe with a live DB.
func TestOnCallHandler_ListIntegrations_ReturnsJSON(t *testing.T) {
	gin.SetMode(gin.TestMode)
	pool := testPool(t)

	h := handlers.NewOnCallHandler(pool, nil)
	r := gin.New()
	r.GET("/admin/oncall", h.ListIntegrations)

	req := httptest.NewRequest(http.MethodGet, "/admin/oncall", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if _, ok := resp["integrations"]; !ok {
		t.Error("response body should contain an 'integrations' key")
	}
}

// TestOnCallHandler_CreateIntegration_MissingName verifies that CreateIntegration
// returns 400 when the required "name" binding field is absent.
func TestOnCallHandler_CreateIntegration_MissingName(t *testing.T) {
	gin.SetMode(gin.TestMode)
	pool := testPool(t)

	h := handlers.NewOnCallHandler(pool, nil)
	r := gin.New()
	r.POST("/admin/oncall", h.CreateIntegration)

	body := map[string]interface{}{
		// name intentionally omitted
		"integration_key": "test-key-1234",
		"provider":        "pagerduty",
	}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/admin/oncall", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing name, got %d: %s", w.Code, w.Body.String())
	}
}

// TestOnCallHandler_CreateIntegration_MissingIntegrationKey verifies that
// CreateIntegration returns 400 when "integration_key" (required binding) is absent.
func TestOnCallHandler_CreateIntegration_MissingIntegrationKey(t *testing.T) {
	gin.SetMode(gin.TestMode)
	pool := testPool(t)

	h := handlers.NewOnCallHandler(pool, nil)
	r := gin.New()
	r.POST("/admin/oncall", h.CreateIntegration)

	body := map[string]interface{}{
		"name":     "Production PagerDuty",
		"provider": "pagerduty",
		// integration_key intentionally omitted
	}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/admin/oncall", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing integration_key, got %d: %s", w.Code, w.Body.String())
	}
}

// TestOnCallHandler_CreateIntegration_InvalidProvider verifies that
// CreateIntegration returns 400 for an unrecognised provider value.
func TestOnCallHandler_CreateIntegration_InvalidProvider(t *testing.T) {
	gin.SetMode(gin.TestMode)
	pool := testPool(t)

	h := handlers.NewOnCallHandler(pool, nil)
	r := gin.New()
	r.POST("/admin/oncall", h.CreateIntegration)

	body := map[string]interface{}{
		"name":            "Bad Provider Integration",
		"integration_key": "key-abcdef",
		"provider":        "unknownprovider",
	}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/admin/oncall", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid provider, got %d: %s", w.Code, w.Body.String())
	}
}

// TestOnCallHandler_GetIntegration_NotFound verifies that fetching a
// non-existent integration ID returns 404.
func TestOnCallHandler_GetIntegration_NotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)
	pool := testPool(t)

	h := handlers.NewOnCallHandler(pool, nil)
	r := gin.New()
	r.GET("/admin/oncall/:id", h.GetIntegration)

	req := httptest.NewRequest(http.MethodGet,
		"/admin/oncall/00000000-0000-0000-0000-000000000000", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for non-existent integration, got %d: %s", w.Code, w.Body.String())
	}
}

// TestOnCallHandler_TriggerAlert_MissingSummary verifies that TriggerAlert
// returns 400 when the required "summary" binding field is omitted.
func TestOnCallHandler_TriggerAlert_MissingSummary(t *testing.T) {
	gin.SetMode(gin.TestMode)
	pool := testPool(t)

	h := handlers.NewOnCallHandler(pool, nil)
	r := gin.New()
	r.POST("/oncall/trigger", h.TriggerAlert)

	body := map[string]interface{}{
		"severity": "critical",
		// summary intentionally omitted
	}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/oncall/trigger", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing summary, got %d: %s", w.Code, w.Body.String())
	}
}

// TestOnCallHandler_MethodNotAllowed verifies that DELETE to the collection
// endpoint returns 405 when HandleMethodNotAllowed is enabled.
func TestOnCallHandler_MethodNotAllowed(t *testing.T) {
	gin.SetMode(gin.TestMode)
	pool := testPool(t)

	h := handlers.NewOnCallHandler(pool, nil)
	r := gin.New()
	r.HandleMethodNotAllowed = true
	r.GET("/admin/oncall", h.ListIntegrations)
	r.POST("/admin/oncall", h.CreateIntegration)

	req := httptest.NewRequest(http.MethodDelete, "/admin/oncall", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// TestOnCallHandler_GetEvents_ReturnsJSON verifies that GetEvents returns 200
// with an "events" key. The tables are auto-created by ensureTables.
func TestOnCallHandler_GetEvents_ReturnsJSON(t *testing.T) {
	gin.SetMode(gin.TestMode)
	pool := testPool(t)

	h := handlers.NewOnCallHandler(pool, nil)
	r := gin.New()
	r.GET("/admin/oncall/:id/events", h.GetEvents)

	req := httptest.NewRequest(http.MethodGet,
		"/admin/oncall/00000000-0000-0000-0000-000000000000/events", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if _, ok := resp["events"]; !ok {
		t.Error("response body should contain an 'events' key")
	}
}
