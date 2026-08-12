package handlers_test

import (
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/edr-platform/server/internal/api/handlers"
	"github.com/edr-platform/server/internal/store"
)

func TestLogAnalysisHandler_ParseRuleCRUD(t *testing.T) {
	db := testDB(t)
	h := handlers.NewLogAnalysisHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/la/rules", h.CreateParseRule)
	r.DELETE("/la/rules/:id", h.DeleteParseRule)
	id := mutID(t, r, "/la/rules", gin.H{"name": "cov-pr", "log_source": "syslog", "pattern": "^ERR", "field_map": gin.H{}})
	delOK(t, r, "/la/rules/"+id)
}

func TestLogIngestionHandler_SourceCRUD(t *testing.T) {
	db := testDB(t)
	h := handlers.NewLogIngestionHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/li/sources", h.CreateSource)
	r.DELETE("/li/sources/:id", h.DeleteSource)
	id := mutID(t, r, "/li/sources", gin.H{"name": "cov-src", "description": "d", "format": "json"})
	delOK(t, r, "/li/sources/"+id)
}

func TestPacketCaptureHandler_CRUD(t *testing.T) {
	db := testDB(t)
	ctx := contextBG()
	var aid string
	if err := db.Pool().QueryRow(ctx,
		`INSERT INTO agents (hostname, os_type, status, last_seen, enrolled_at)
		 VALUES ('cov-pcap-h', 'linux', 'online', NOW(), NOW()) RETURNING id::text`).Scan(&aid); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Pool().Exec(ctx, "DELETE FROM agents WHERE id=$1", aid) })
	h := handlers.NewPacketCaptureHandler(store.NewPacketCaptureStore(db.Pool()))
	r, _ := authRouter(t, db)
	r.POST("/pcap", h.Create)
	r.DELETE("/pcap/:id", h.Delete)
	id := mutID(t, r, "/pcap", gin.H{"agent_id": aid, "name": "cov-pcap", "filter": "tcp", "interface_name": "eth0", "max_packets": 100, "max_size_mb": 10, "duration_seconds": 60})
	delOK(t, r, "/pcap/"+id)
}

func TestAccessReviewHandler_CreateCampaign(t *testing.T) {
	db := testDB(t)
	h := handlers.NewAccessReviewHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/ar", h.CreateCampaign)
	_ = mutID(t, r, "/ar", gin.H{"name": "cov-camp", "description": "d", "reviewer": "cov-reviewer", "due_date": "2026-12-31"})
}
