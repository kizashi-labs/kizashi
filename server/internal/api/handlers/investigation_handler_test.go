package handlers_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/edr-platform/server/internal/api/handlers"
)

// ─── InvestigationHandler – nil investigator (no API key configured) ─────────

func TestGetInvestigation_NilInvestigator(t *testing.T) {
	gin.SetMode(gin.TestMode)

	h := handlers.NewInvestigationHandler(nil)
	r := gin.New()
	r.GET("/alerts/:id/investigation", h.GetInvestigation)

	req := httptest.NewRequest(http.MethodGet, "/alerts/abc-123/investigation", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("nilインベスティゲーター: 200を期待しましたが %d が返りました", w.Code)
	}

	var body map[string]any
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("レスポンスのデコードに失敗: %v", err)
	}

	if available, _ := body["available"].(bool); available {
		t.Error("available は false であるべきです（調査が未設定のため）")
	}
	if body["alert_id"] != "abc-123" {
		t.Errorf("alert_id: got %v, want abc-123", body["alert_id"])
	}
	if body["summary"] == "" {
		t.Error("summary フィールドが空です")
	}
}

func TestInvestigate_NilInvestigator_Returns503(t *testing.T) {
	gin.SetMode(gin.TestMode)

	h := handlers.NewInvestigationHandler(nil)
	r := gin.New()
	r.POST("/alerts/:id/investigate", h.Investigate)

	req := httptest.NewRequest(http.MethodPost, "/alerts/xyz-999/investigate", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("nilインベスティゲーター: 503を期待しましたが %d が返りました", w.Code)
	}

	var body map[string]any
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("レスポンスのデコードに失敗: %v", err)
	}
	if body["error"] == "" {
		t.Error("error フィールドが空です")
	}
}

func TestGetInvestigation_RouteParam_Propagated(t *testing.T) {
	gin.SetMode(gin.TestMode)

	h := handlers.NewInvestigationHandler(nil)
	r := gin.New()
	r.GET("/alerts/:id/investigation", h.GetInvestigation)

	alertID := "11111111-2222-3333-4444-555555555555"
	req := httptest.NewRequest(http.MethodGet, "/alerts/"+alertID+"/investigation", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	var body map[string]any
	_ = json.NewDecoder(w.Body).Decode(&body)

	if body["alert_id"] != alertID {
		t.Errorf("alert_id: got %v, want %s", body["alert_id"], alertID)
	}
}
