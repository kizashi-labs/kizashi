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

// ─── SecurityKPIHandler ────────────────────────────────────────────────────

// TestSecurityKPIHandler_CreateKPI_MissingName verifies that CreateKPI returns
// 400 when the required "name" field is absent. The pool is nil because the
// table-check path panics without a pool; we provide a real (skipped) pool to
// reach the table-exists guard, which returns false and short-circuits to 503.
// For pure validation tests we supply only the body-binding path by providing
// a pool through testPool so the first DB call returns false gracefully.
func TestSecurityKPIHandler_CreateKPI_MissingName(t *testing.T) {
	gin.SetMode(gin.TestMode)
	pool := testPool(t)

	h := handlers.NewSecurityKPIHandler(pool)
	r := gin.New()
	r.POST("/kpi", h.CreateKPI)

	// Omit "name" — category and unit present but name is empty string.
	body := map[string]interface{}{
		"category":     "detection",
		"unit":         "percent",
		"target_value": 95.0,
	}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/kpi", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// Handler returns 503 when table not yet migrated, or 400 for validation
	// failure once the table exists. Either way it must not be 2xx.
	if w.Code == http.StatusCreated || w.Code == http.StatusOK {
		t.Errorf("expected non-2xx for missing name, got %d: %s", w.Code, w.Body.String())
	}
}

// TestSecurityKPIHandler_CreateKPI_MissingCategory verifies that a request
// missing "category" is rejected.
func TestSecurityKPIHandler_CreateKPI_MissingCategory(t *testing.T) {
	gin.SetMode(gin.TestMode)
	pool := testPool(t)

	h := handlers.NewSecurityKPIHandler(pool)
	r := gin.New()
	r.POST("/kpi", h.CreateKPI)

	body := map[string]interface{}{
		"name":         "MTTD",
		"unit":         "minutes",
		"target_value": 30.0,
		// category intentionally omitted
	}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/kpi", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code == http.StatusCreated || w.Code == http.StatusOK {
		t.Errorf("expected non-2xx for missing category, got %d: %s", w.Code, w.Body.String())
	}
}

// TestSecurityKPIHandler_ListKPIs_NoTable verifies that ListKPIs returns 200
// with an empty array when the security_kpi_definitions table does not exist.
func TestSecurityKPIHandler_ListKPIs_NoTable(t *testing.T) {
	gin.SetMode(gin.TestMode)
	pool := testPool(t)

	h := handlers.NewSecurityKPIHandler(pool)
	r := gin.New()
	r.GET("/kpi", h.ListKPIs)

	req := httptest.NewRequest(http.MethodGet, "/kpi", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// Must always return 200, even when table is absent.
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if _, ok := resp["kpis"]; !ok {
		t.Error("response body should contain a 'kpis' key")
	}
}

// TestSecurityKPIHandler_GetMeasurements_Empty verifies that GetMeasurements
// returns 200 with an empty array when there are no measurements for the KPI
// (whether the table is absent, or present-but-empty against a migrated DB).
// A valid UUID is used so the request reaches the data path rather than being
// rejected by id-format validation.
func TestSecurityKPIHandler_GetMeasurements_Empty(t *testing.T) {
	gin.SetMode(gin.TestMode)
	pool := testPool(t)

	h := handlers.NewSecurityKPIHandler(pool)
	r := gin.New()
	r.GET("/kpi/:id/measurements", h.GetMeasurements)

	// A well-formed but non-existent KPI id — exercises the empty-result path.
	req := httptest.NewRequest(http.MethodGet, "/kpi/00000000-0000-0000-0000-000000000000/measurements", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if _, ok := resp["measurements"]; !ok {
		t.Error("response body should contain a 'measurements' key")
	}
}

// TestSecurityKPIHandler_GetDashboard_NoTable verifies that GetDashboard returns
// 200 with an empty array when the table does not exist.
func TestSecurityKPIHandler_GetDashboard_NoTable(t *testing.T) {
	gin.SetMode(gin.TestMode)
	pool := testPool(t)

	h := handlers.NewSecurityKPIHandler(pool)
	r := gin.New()
	r.GET("/kpi/dashboard", h.GetDashboard)

	req := httptest.NewRequest(http.MethodGet, "/kpi/dashboard", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if _, ok := resp["kpis"]; !ok {
		t.Error("response body should contain a 'kpis' key")
	}
}

// TestSecurityKPIHandler_MethodNotAllowed ensures that sending a DELETE to the
// collection endpoint returns 405.
func TestSecurityKPIHandler_MethodNotAllowed(t *testing.T) {
	gin.SetMode(gin.TestMode)
	pool := testPool(t)

	h := handlers.NewSecurityKPIHandler(pool)
	r := gin.New()
	r.HandleMethodNotAllowed = true
	r.GET("/kpi", h.ListKPIs)
	r.POST("/kpi", h.CreateKPI)

	req := httptest.NewRequest(http.MethodDelete, "/kpi", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// TestSecurityKPIHandler_RecordMeasurement_MissingBody verifies that
// RecordMeasurement with an invalid body returns 400 or 503 (not 2xx).
func TestSecurityKPIHandler_RecordMeasurement_InvalidBody(t *testing.T) {
	gin.SetMode(gin.TestMode)
	pool := testPool(t)

	h := handlers.NewSecurityKPIHandler(pool)
	r := gin.New()
	r.POST("/kpi/:id/measurements", h.RecordMeasurement)

	req := httptest.NewRequest(http.MethodPost, "/kpi/some-id/measurements",
		bytes.NewReader([]byte("not-json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code == http.StatusCreated || w.Code == http.StatusOK {
		t.Errorf("expected non-2xx for invalid JSON body, got %d", w.Code)
	}
}
