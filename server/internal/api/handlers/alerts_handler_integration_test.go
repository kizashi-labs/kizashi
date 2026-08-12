package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/edr-platform/server/internal/api/handlers"
	"github.com/edr-platform/server/internal/store"
)

// TestAlertHandler_Integration_Lifecycle exercises the alert Get/Update handlers
// end-to-end against a real (migrated) database: save an alert, fetch it, change
// its status, and confirm the change is persisted.
func TestAlertHandler_Integration_Lifecycle(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := testDB(t)
	agentStore := store.NewAgentStore(db)
	alertStore := store.NewAlertStore(db)
	h := handlers.NewAlertHandler(alertStore, agentStore)

	ctx := context.Background()
	const agentID = "b2b2b2b2-c3c3-d4d4-e5e5-f6f6f6f6f6f6"
	const alertID = "c3c3c3c3-d4d4-e5e5-f6f6-a7a7a7a7a7a7"

	cleanup := func() {
		_, _ = db.Pool().Exec(ctx, "DELETE FROM alerts WHERE id=$1", alertID)
		_, _ = db.Pool().Exec(ctx, "DELETE FROM agents WHERE id=$1", agentID)
	}
	cleanup()
	t.Cleanup(cleanup)

	// Alerts reference an agent — create it first to satisfy any FK.
	if err := agentStore.UpsertAgent(ctx, &store.AgentRow{
		ID: agentID, Hostname: "itest-alert-host", OSType: "windows",
		OSVersion: "11", AgentVersion: "1.0.0", IPAddresses: []string{"10.0.0.9"}, Status: "online",
	}); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}

	if err := alertStore.SaveAlert(ctx, &store.StoredAlert{
		ID:        alertID,
		AgentID:   agentID,
		Hostname:  "itest-alert-host",
		OS:        "windows",
		Severity:  8,
		Status:    "open",
		Title:     "Integration test alert",
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("SaveAlert: %v", err)
	}

	r := gin.New()
	r.GET("/alerts/:id", h.Get)
	r.PUT("/alerts/:id", h.Update)

	// ── Get returns the alert with status "open" ────────────────────────────
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/alerts/"+alertID, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("Get: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var alert map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &alert); err != nil {
		t.Fatalf("Get: invalid JSON: %v", err)
	}
	if alert["id"] != alertID || alert["status"] != "open" {
		t.Errorf("Get: unexpected alert: %+v", alert)
	}

	// ── Update status open → investigating ──────────────────────────────────
	body, _ := json.Marshal(map[string]string{"status": "investigating"})
	w = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/alerts/"+alertID, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Update: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// ── Get reflects the new status ─────────────────────────────────────────
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/alerts/"+alertID, nil))
	var updated map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &updated); err != nil {
		t.Fatalf("Get(after update): invalid JSON: %v", err)
	}
	if updated["status"] != "investigating" {
		t.Errorf("status not persisted: got %v, want investigating", updated["status"])
	}

	// ── Get on a non-existent id → 404 ──────────────────────────────────────
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/alerts/00000000-0000-0000-0000-000000000000", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("Get(nonexistent): expected 404, got %d", w.Code)
	}
}
