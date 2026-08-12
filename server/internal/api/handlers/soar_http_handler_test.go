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

// ─── SOARHandler – HTTP integration tests ─────────────────────────────────────

// TestSOARHandler_CreateConfig_MissingName verifies that CreateConfig returns
// 400 when the required "name" field is absent.
func TestSOARHandler_CreateConfig_MissingName(t *testing.T) {
	gin.SetMode(gin.TestMode)
	pool := testPool(t)

	h := handlers.NewSOARHandler(pool)
	r := gin.New()
	r.POST("/soar/configs", h.CreateConfig)

	body := map[string]interface{}{
		// name intentionally omitted
		"type":    "jira",
		"enabled": true,
	}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/soar/configs", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing name, got %d: %s", w.Code, w.Body.String())
	}
}

// TestSOARHandler_CreateConfig_MissingType verifies that CreateConfig returns
// 400 when the required "type" field is absent.
func TestSOARHandler_CreateConfig_MissingType(t *testing.T) {
	gin.SetMode(gin.TestMode)
	pool := testPool(t)

	h := handlers.NewSOARHandler(pool)
	r := gin.New()
	r.POST("/soar/configs", h.CreateConfig)

	body := map[string]interface{}{
		"name":    "My SOAR Config",
		"enabled": true,
		// type intentionally omitted
	}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/soar/configs", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing type, got %d: %s", w.Code, w.Body.String())
	}
}

// TestSOARHandler_CreateConfig_InvalidType verifies that CreateConfig returns
// 400 when "type" is not "jira" or "servicenow".
func TestSOARHandler_CreateConfig_InvalidType(t *testing.T) {
	gin.SetMode(gin.TestMode)
	pool := testPool(t)

	h := handlers.NewSOARHandler(pool)
	r := gin.New()
	r.POST("/soar/configs", h.CreateConfig)

	body := map[string]interface{}{
		"name":    "PagerDuty Config",
		"type":    "pagerduty", // not jira/servicenow
		"enabled": true,
	}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/soar/configs", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid type, got %d: %s", w.Code, w.Body.String())
	}
}

// TestSOARHandler_CreateTicket_MissingConfigID verifies that CreateTicket
// returns 400 when the required "config_id" field is absent.
func TestSOARHandler_CreateTicket_MissingConfigID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	pool := testPool(t)

	h := handlers.NewSOARHandler(pool)
	r := gin.New()
	r.POST("/incidents/:id/ticket", h.CreateTicket)

	body := map[string]interface{}{
		// config_id intentionally omitted
	}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost,
		"/incidents/00000000-0000-0000-0000-000000000001/ticket",
		bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing config_id, got %d: %s", w.Code, w.Body.String())
	}
}

// TestSOARHandler_UpdateConfig_NotFound verifies that UpdateConfig returns
// 404 when the given config ID does not exist in the database.
func TestSOARHandler_UpdateConfig_NotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)
	pool := testPool(t)

	h := handlers.NewSOARHandler(pool)
	r := gin.New()
	r.PATCH("/soar/configs/:id", h.UpdateConfig)

	body := map[string]interface{}{
		"enabled": false,
	}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPatch,
		"/soar/configs/00000000-0000-0000-0000-000000000000",
		bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for non-existent config, got %d: %s", w.Code, w.Body.String())
	}
}

// TestSOARHandler_DeleteConfig_NotFound verifies that DeleteConfig returns
// 404 when the given ID does not exist.
func TestSOARHandler_DeleteConfig_NotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)
	pool := testPool(t)

	h := handlers.NewSOARHandler(pool)
	r := gin.New()
	r.DELETE("/soar/configs/:id", h.DeleteConfig)

	req := httptest.NewRequest(http.MethodDelete,
		"/soar/configs/00000000-0000-0000-0000-000000000000", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for non-existent config, got %d: %s", w.Code, w.Body.String())
	}
}

// TestSOARHandler_MethodNotAllowed verifies that PUT to the collection endpoint
// returns 405 when HandleMethodNotAllowed is enabled.
func TestSOARHandler_MethodNotAllowed(t *testing.T) {
	gin.SetMode(gin.TestMode)
	pool := testPool(t)

	h := handlers.NewSOARHandler(pool)
	r := gin.New()
	r.HandleMethodNotAllowed = true
	r.GET("/soar/configs", h.ListConfigs)
	r.POST("/soar/configs", h.CreateConfig)

	req := httptest.NewRequest(http.MethodPut, "/soar/configs", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// TestSOARHandler_TestConfig_NotFound verifies that TestConfig returns 404
// when the config ID does not exist in the database.
func TestSOARHandler_TestConfig_NotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)
	pool := testPool(t)

	h := handlers.NewSOARHandler(pool)
	r := gin.New()
	r.POST("/soar/configs/:id/test", h.TestConfig)

	req := httptest.NewRequest(http.MethodPost,
		"/soar/configs/00000000-0000-0000-0000-000000000000/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for non-existent config, got %d: %s", w.Code, w.Body.String())
	}
}
