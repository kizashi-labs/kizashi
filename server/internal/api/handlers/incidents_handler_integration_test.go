package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/edr-platform/server/internal/api/handlers"
	"github.com/edr-platform/server/internal/store"
)

// TestIncidentHandler_Integration_CreateUpdate exercises the incident
// Create/Get/Update handlers end-to-end against a real (migrated) database.
func TestIncidentHandler_Integration_CreateUpdate(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := testDB(t)
	incStore := store.NewIncidentStore(db)
	// Pool left nil so Create skips the best-effort SOAR auto-ticket goroutine.
	h := &handlers.IncidentHandler{Store: incStore}

	r := gin.New()
	r.POST("/incidents", h.Create)
	r.GET("/incidents/:id", h.Get)
	r.PUT("/incidents/:id", h.Update)

	do := func(method, target string, body []byte) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		var req *http.Request
		if body != nil {
			req = httptest.NewRequest(method, target, bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
		} else {
			req = httptest.NewRequest(method, target, nil)
		}
		r.ServeHTTP(w, req)
		return w
	}

	// ── Create ──────────────────────────────────────────────────────────────
	createBody, _ := json.Marshal(map[string]interface{}{
		"title": "Integration incident", "description": "from test", "severity": 8, "status": "open",
	})
	w := do(http.MethodPost, "/incidents", createBody)
	if w.Code != http.StatusCreated {
		t.Fatalf("Create: expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil || created.ID == "" {
		t.Fatalf("Create: could not parse id from response: %v (%s)", err, w.Body.String())
	}
	id := created.ID
	t.Cleanup(func() { _, _ = db.Pool().Exec(context.Background(), "DELETE FROM incidents WHERE id=$1", id) })

	// ── Get reflects the created incident ───────────────────────────────────
	w = do(http.MethodGet, "/incidents/"+id, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("Get: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	// Get returns {"incident": {...}, "alerts": [...]}.
	inc := getIncident(t, w)
	if inc["title"] != "Integration incident" || inc["status"] != "open" {
		t.Errorf("Get: unexpected incident: %+v", inc)
	}

	// ── Update status open → resolved ───────────────────────────────────────
	updateBody, _ := json.Marshal(map[string]interface{}{
		"title": "Integration incident", "status": "resolved", "severity": 8,
	})
	if w := do(http.MethodPut, "/incidents/"+id, updateBody); w.Code != http.StatusOK {
		t.Fatalf("Update: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// ── Get reflects the new status ─────────────────────────────────────────
	w = do(http.MethodGet, "/incidents/"+id, nil)
	if updated := getIncident(t, w); updated["status"] != "resolved" {
		t.Errorf("status not persisted: got %v, want resolved", updated["status"])
	}

	// ── Update with a malformed id → 400 ────────────────────────────────────
	if w := do(http.MethodPut, "/incidents/not-a-uuid", updateBody); w.Code != http.StatusBadRequest {
		t.Errorf("Update(bad id): expected 400, got %d", w.Code)
	}
}

// getIncident extracts the nested "incident" object from a Get response
// ({"incident": {...}, "alerts": [...]}).
func getIncident(t *testing.T, w *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("Get: invalid JSON: %v", err)
	}
	inc, ok := body["incident"].(map[string]interface{})
	if !ok {
		t.Fatalf("Get: response missing 'incident' object: %+v", body)
	}
	return inc
}
