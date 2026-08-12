package handlers_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/edr-platform/server/internal/api/handlers"
)

// TestEncryptionMgmt_ListEndpointStatus_RealData proves the encryption-mgmt UI
// visualization fix: ListEndpointStatus/GetStats now read the real
// endpoint_encryption table (populated by the agent reporter) instead of the
// former hardcoded mock.
func TestEncryptionMgmt_ListEndpointStatus_RealData(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	gin.SetMode(gin.TestMode)

	var agentID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO agents (hostname, os_type, status, last_seen, enrolled_at)
		 VALUES ('viz-enc-host', 'linux', 'online', NOW(), NOW()) RETURNING id::text`).Scan(&agentID); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, "DELETE FROM endpoint_encryption WHERE agent_id=$1", agentID)
		_, _ = pool.Exec(ctx, "DELETE FROM agents WHERE id=$1", agentID)
	})
	if _, err := pool.Exec(ctx,
		`INSERT INTO endpoint_encryption (agent_id, encrypted, method, details)
		 VALUES ($1::uuid, TRUE, 'LUKS', 'dm-0')`, agentID); err != nil {
		t.Fatalf("seed encryption: %v", err)
	}

	h := handlers.NewEncryptionMgmtHandler(pool)
	r := gin.New()
	r.GET("/encryption/endpoints", h.ListEndpointStatus)
	r.GET("/encryption/stats", h.GetStats)

	// endpoints list contains our seeded host as encrypted/compliant.
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/encryption/endpoints", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("endpoints: expected 200, got %d", w.Code)
	}
	var listResp struct {
		Endpoints []map[string]any `json:"endpoints"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("endpoints JSON: %v", err)
	}
	found := false
	for _, e := range listResp.Endpoints {
		if e["hostname"] == "viz-enc-host" {
			found = true
			if e["status"] != "encrypted" || e["compliance_status"] != "compliant" {
				t.Errorf("seeded host wrong status: %+v", e)
			}
		}
	}
	if !found {
		t.Fatalf("seeded encrypted host not present in endpoints response")
	}

	// stats reflect at least one encrypted endpoint.
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/encryption/stats", nil))
	var stats struct {
		Total     int `json:"total_endpoints"`
		Encrypted int `json:"encrypted"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &stats); err != nil {
		t.Fatalf("stats JSON: %v", err)
	}
	if stats.Total < 1 || stats.Encrypted < 1 {
		t.Errorf("stats did not reflect seeded encrypted endpoint: %+v", stats)
	}
}

// TestEndpointHardening_ListAssessments_RealData proves the hardening UI
// visualization fix: after consolidating on the 171 hardening_* schema, the
// admin read handler surfaces the per-agent assessment the agent reporter writes.
func TestEndpointHardening_ListAssessments_RealData(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	gin.SetMode(gin.TestMode)

	var agentID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO agents (hostname, os_type, status, last_seen, enrolled_at)
		 VALUES ('viz-hard-host', 'linux', 'online', NOW(), NOW()) RETURNING id::text`).Scan(&agentID); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	var baselineID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO hardening_baselines (name, os_type, framework)
		 VALUES ('viz-hardening', 'linux', 'cis') RETURNING id::text`).Scan(&baselineID); err != nil {
		t.Fatalf("seed baseline: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, "DELETE FROM hardening_assessments WHERE agent_id=$1", agentID)
		_, _ = pool.Exec(ctx, "DELETE FROM hardening_baselines WHERE id=$1", baselineID)
		_, _ = pool.Exec(ctx, "DELETE FROM agents WHERE id=$1", agentID)
	})
	if _, err := pool.Exec(ctx,
		`INSERT INTO hardening_assessments
		   (baseline_id, agent_id, passed_checks, failed_checks, score, status)
		 VALUES ($1::uuid, $2::uuid, 3, 1, 75, 'completed')`,
		baselineID, agentID); err != nil {
		t.Fatalf("seed assessment: %v", err)
	}

	h := handlers.NewEndpointHardeningHandler(pool)
	r := gin.New()
	r.GET("/hardening/assessments", h.ListAssessments)
	r.GET("/hardening/stats", h.Stats)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/hardening/assessments", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("assessments: expected 200, got %d", w.Code)
	}
	var listResp struct {
		Assessments []map[string]any `json:"assessments"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("assessments JSON: %v", err)
	}
	found := false
	for _, a := range listResp.Assessments {
		if a["hostname"] == "viz-hard-host" {
			found = true
		}
	}
	if !found {
		t.Fatalf("seeded hardening assessment not present in response")
	}

	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/hardening/stats", nil))
	var stats struct {
		TotalAssessments int `json:"total_assessments"`
		ActiveBaselines  int `json:"active_baselines"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &stats); err != nil {
		t.Fatalf("stats JSON: %v", err)
	}
	if stats.TotalAssessments < 1 || stats.ActiveBaselines < 1 {
		t.Errorf("hardening stats did not reflect seeded data: %+v", stats)
	}
}
