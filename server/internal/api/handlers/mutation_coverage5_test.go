package handlers_test

import (
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/edr-platform/server/internal/api/handlers"
)

func TestMetricsReportHandler_CRUD(t *testing.T) {
	db := testDB(t)
	h := handlers.NewMetricsReportHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/mr", h.CreateSchedule)
	r.DELETE("/mr/:id", h.DeleteSchedule)
	id := mutID(t, r, "/mr", gin.H{"name": "cov-mr", "report_type": "executive_summary", "description": "d", "schedule": "weekly", "recipients": []string{"cov@example.com"}, "parameters": gin.H{}})
	delOK(t, r, "/mr/"+id)
}

func TestRBACHandler_CreateRole(t *testing.T) {
	db := testDB(t)
	h := handlers.NewRBACHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/rbac", h.CreateRole)
	if w := jsonReq(r, http.MethodPost, "/rbac", gin.H{"name": "cov-role-" + uuidShort(), "description": "d", "color": "#0af"}); w.Code >= 400 {
		t.Fatalf("CreateRole = %d: %s", w.Code, w.Body.String())
	}
}

func TestSecuritySLAHandler_Create(t *testing.T) {
	db := testDB(t)
	h := handlers.NewSecuritySLAHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/sla", h.CreatePolicy)
	_ = mutID(t, r, "/sla", gin.H{"name": "cov-sla", "severity": "high", "response_minutes": 30, "resolution_hours": 4, "escalation_hours": 2})
}

func TestTrainingHandler_Create(t *testing.T) {
	db := testDB(t)
	h := handlers.NewTrainingHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/tr", h.CreateCampaign)
	_ = mutID(t, r, "/tr", gin.H{"name": "cov-training", "campaign_type": "phishing", "target_count": 10})
}

func TestForensicsAutomationHandler_Create(t *testing.T) {
	db := testDB(t)
	h := handlers.NewForensicsAutomationHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/fa", h.CreateJob)
	_ = mutID(t, r, "/fa", gin.H{"name": "cov-fa", "trigger_type": "manual", "priority": "high", "assigned_analyst": "cov"})
}

func TestQuarantineActionsHandler_Create(t *testing.T) {
	db := testDB(t)
	ctx := contextBG()
	var aid string
	if err := db.Pool().QueryRow(ctx,
		`INSERT INTO agents (hostname, os_type, status, last_seen, enrolled_at)
		 VALUES ('cov-qa', 'linux', 'online', NOW(), NOW()) RETURNING id::text`).Scan(&aid); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Pool().Exec(ctx, "DELETE FROM agents WHERE id=$1", aid) })
	h := handlers.NewQuarantineActionsHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/qa", h.Create)
	if w := jsonReq(r, http.MethodPost, "/qa", gin.H{"agent_id": aid, "reason": "cov", "network_isolated": true, "process_killed": false}); w.Code >= 400 {
		t.Fatalf("Create = %d: %s", w.Code, w.Body.String())
	}
}

func uuidShort() string { return "cov-" + uuid.NewString()[:8] }
