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

// TestSoftwareVulnerability_List_SurfacesScannerResults proves the software-vuln
// visualization fix: List now surfaces the live scanner's real results from the
// vulnerabilities table (previously it only read the never-populated
// vulnerability_findings, then a heuristic over endpoint_software).
func TestSoftwareVulnerability_List_SurfacesScannerResults(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	gin.SetMode(gin.TestMode)

	var agentID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO agents (hostname, os_type, status, last_seen, enrolled_at)
		 VALUES ('viz-vuln-host', 'linux', 'online', NOW(), NOW()) RETURNING id::text`).Scan(&agentID); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, "DELETE FROM vulnerabilities WHERE agent_id=$1", agentID)
		_, _ = pool.Exec(ctx, "DELETE FROM agents WHERE id=$1", agentID)
	})
	// A real scanner finding (as VulnerabilityScanner would write it).
	if _, err := pool.Exec(ctx,
		`INSERT INTO vulnerabilities
		   (agent_id, cve_id, title, severity, cvss_score, affected_package, affected_version, fixed_version, status)
		 VALUES ($1::uuid, 'CVE-2099-0001', 'openssl flaw', 'high', 7.5, 'openssl', '3.0.2', '3.0.7', 'open')`,
		agentID); err != nil {
		t.Fatalf("seed vulnerability: %v", err)
	}

	h := handlers.NewSoftwareVulnerabilityHandler(pool)
	r := gin.New()
	r.GET("/software-inventory", h.List)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/software-inventory", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	found := false
	for _, it := range resp.Data {
		if it["cve_id"] == "CVE-2099-0001" && it["hostname"] == "viz-vuln-host" {
			found = true
			if it["name"] != "openssl" || it["severity"] != "high" {
				t.Errorf("scanner finding mapped wrong: %+v", it)
			}
		}
	}
	if !found {
		t.Fatalf("seeded scanner vulnerability not surfaced by List (vulnerability_findings may be non-empty in this DB)")
	}
}
