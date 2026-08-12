package handlers_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/edr-platform/server/internal/api/handlers"
)

// TestBugfix_RiskScores_CountsAlertSeverity proves the alerts-severity scale fix:
// the RiskScores query buckets alert severity on the 1–10 scale (>=9 critical),
// where it previously used a 0–100 scale (>=90) that never matched the smallint
// column, so an agent whose only risk was a critical alert never appeared.
func TestBugfix_RiskScores_CountsAlertSeverity(t *testing.T) {
	db := testDB(t)
	ctx := contextBG()

	var aid string
	if err := db.Pool().QueryRow(ctx,
		`INSERT INTO agents (hostname, os_type, status, last_seen, enrolled_at)
		 VALUES ('cov-riskfix', 'linux', 'online', NOW(), NOW()) RETURNING id::text`).Scan(&aid); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Pool().Exec(ctx, "DELETE FROM agents WHERE id=$1", aid) })
	if _, err := db.Pool().Exec(ctx,
		`INSERT INTO alerts (agent_id, severity, title, description, status, created_at)
		 VALUES ($1::uuid, 9, 'cov-riskfix-alert', 'd', 'open', NOW())`, aid); err != nil {
		t.Fatalf("seed alert: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Pool().Exec(ctx, "DELETE FROM alerts WHERE agent_id=$1", aid) })

	h := &handlers.AgentHandler{Pool: db.Pool()}
	r := gin.New()
	r.GET("/risk-scores", h.RiskScores)

	w := jsonReq(r, http.MethodGet, "/risk-scores", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("RiskScores = %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), aid) {
		t.Fatalf("agent with a critical (severity 9) alert missing from risk scores: %s", w.Body.String())
	}
}
