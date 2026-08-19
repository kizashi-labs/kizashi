package handlers_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/edr-platform/server/internal/api/handlers"
)

// TestCov8_* exercises Create/Update/Delete/Toggle/Approve mutation methods on
// handlers that had 0% coverage on those paths. Most of these handlers are
// stateless "echo" endpoints (the pool is accepted but unused on the mutation
// path), so a valid JSON body is enough to drive them; a handful hit the DB and
// seed/guard accordingly. Assertions are lenient (createID or w.Code < 400).

func TestCov8_EncryptionMgmtHandler(t *testing.T) {
	db := testDB(t)
	h := handlers.NewEncryptionMgmtHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/policies", h.CreatePolicy)
	_ = createID(t, r, "/policies", gin.H{"name": "cov8-enc", "encryption_type": "full_disk", "algorithm": "AES-256", "enforcement_mode": "enforce"})
}

func TestCov8_NTAHandler(t *testing.T) {
	db := testDB(t)
	h := handlers.NewNTAHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/rules", h.CreateRule)
	_ = createID(t, r, "/rules", gin.H{"name": "cov8-nta", "rule_type": "signature", "protocol": "TCP", "severity": "high"})
}

func TestCov8_ZTNAHandler(t *testing.T) {
	db := testDB(t)
	h := handlers.NewZTNAHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/policies", h.CreatePolicy)
	_ = createID(t, r, "/policies", gin.H{"name": "cov8-ztna", "policy_type": "access", "enforcement_mode": "enforce", "priority": 10, "enabled": true})
}

func TestCov8_SupplyChainRiskHandler(t *testing.T) {
	db := testDB(t)
	h := handlers.NewSupplyChainRiskHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/vendors", h.CreateVendor)
	_ = createID(t, r, "/vendors", gin.H{"name": "cov8-vendor", "vendor_type": "software", "criticality": "high"})
}

func TestCov8_DarkWebHandler(t *testing.T) {
	db := testDB(t)
	h := handlers.NewDarkWebHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.PUT("/findings/:id", h.UpdateFinding)
	if w := jsonReq(r, http.MethodPut, "/findings/"+uuid.NewString(), gin.H{"status": "resolved"}); w.Code >= 400 {
		t.Errorf("update finding = %d: %s", w.Code, w.Body.String())
	}
}

func TestCov8_FeedAnalyticsHandler(t *testing.T) {
	db := testDB(t)
	h := handlers.NewFeedAnalyticsHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.PUT("/feeds/:id/status", h.UpdateStatus)
	if w := jsonReq(r, http.MethodPut, "/feeds/"+uuid.NewString()+"/status", gin.H{"status": "disabled"}); w.Code >= 400 {
		t.Errorf("update status = %d: %s", w.Code, w.Body.String())
	}
}

func TestCov8_NetworkSegmentationHandler(t *testing.T) {
	db := testDB(t)
	h := handlers.NewNetworkSegmentationHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/segments", h.CreateSegment)
	r.POST("/policies", h.CreatePolicy)
	r.DELETE("/policies/:id", h.DeletePolicy)

	segID := createID(t, r, "/segments", gin.H{"name": "cov8-seg-" + uuidShort(), "cidr": "10.44.0.0/24", "vlan_id": 44, "gateway": "10.44.0.1", "status": "active"})
	t.Cleanup(func() { _, _ = db.Pool().Exec(contextBG(), "DELETE FROM network_segments WHERE id=$1", segID) })

	polID := createID(t, r, "/policies", gin.H{"from_segment": "DMZ", "to_segment": "CORP", "action": "deny", "protocol": "TCP", "ports": "443"})
	if w := jsonReq(r, http.MethodDelete, "/policies/"+polID, nil); w.Code >= 400 {
		t.Errorf("delete policy = %d: %s", w.Code, w.Body.String())
	}
}

// 未実装のハンドラは、書き込みも 501 で答えます。
//
// **ここは 201 を期待していました。** 作り物のデータを返していた頃の
// 期待がそのまま残っていて、作り物をやめた側が「壊れた」ことになります。
// SDK の検査が間違った宛先を留めていたのと同じ形で、これで3度目です。
//
// 検査するのは3つ:
//
//	501 であること              4xx でも 500 でもありません。
//	`unimplemented` の印        読んだ側が「待っても来ない」と分かる印です。
//	`data` を同梱しないこと      同梱すると、先に data を読む client には
//	                            以前と同じ「空」に見えます。
func TestCov8_UnimplementedHandlersRefuseWrites(t *testing.T) {
	db := testDB(t)

	type write struct {
		method string
		path   string
		body   gin.H
	}
	cases := []struct {
		name   string
		routes func(r *gin.Engine)
		writes []write
	}{
		{"alert-routing", func(r *gin.Engine) {
			h := handlers.NewAlertRoutingHandler(db.Pool())
			r.POST("/rules", h.CreateRule)
			r.PUT("/rules/:id", h.UpdateRule)
			r.DELETE("/rules/:id", h.DeleteRule)
			r.POST("/dests", h.CreateDestination)
		}, []write{
			{http.MethodPost, "/rules", gin.H{"name": "x", "priority": 10}},
			{http.MethodPut, "/rules/" + uuid.NewString(), gin.H{"name": "y"}},
			{http.MethodDelete, "/rules/" + uuid.NewString(), nil},
			{http.MethodPost, "/dests", gin.H{"name": "z", "destination_type": "slack"}},
		}},
		{"security-governance", func(r *gin.Engine) {
			h := handlers.NewSecurityGovernanceHandler(db.Pool())
			r.POST("/policies", h.CreatePolicy)
			r.PUT("/policies/:id", h.UpdatePolicy)
			r.POST("/exceptions/:id/approve", h.ApproveException)
		}, []write{
			{http.MethodPost, "/policies", gin.H{"title": "x", "category": "governance"}},
			{http.MethodPut, "/policies/" + uuid.NewString(), gin.H{"status": "published"}},
			{http.MethodPost, "/exceptions/" + uuid.NewString() + "/approve", nil},
		}},
		{"security-assessment", func(r *gin.Engine) {
			h := handlers.NewSecurityAssessmentHandler(db.Pool())
			r.POST("/assessments", h.CreateAssessment)
			r.PUT("/assessments/:id", h.UpdateAssessment)
		}, []write{
			{http.MethodPost, "/assessments", gin.H{"name": "x", "framework": "ISO27001"}},
			{http.MethodPut, "/assessments/" + uuid.NewString(), gin.H{"status": "review"}},
		}},
		{"itdr", func(r *gin.Engine) {
			h := handlers.NewITDRHandler(db.Pool())
			r.POST("/rules", h.CreateRule)
		}, []write{
			{http.MethodPost, "/rules", gin.H{"name": "x", "severity": "high"}},
		}},
		{"drp", func(r *gin.Engine) {
			h := handlers.NewDRPHandler(db.Pool())
			r.POST("/monitors", h.CreateMonitor)
			r.PUT("/findings/:id", h.UpdateFinding)
		}, []write{
			{http.MethodPost, "/monitors", gin.H{"name": "x", "monitor_type": "brand"}},
			{http.MethodPut, "/findings/" + uuid.NewString(), gin.H{"status": "investigating"}},
		}},
		{"automation-enhanced", func(r *gin.Engine) {
			h := handlers.NewAutomationEnhancedHandler(db.Pool())
			r.POST("/triggers", h.CreateTrigger)
		}, []write{
			{http.MethodPost, "/triggers", gin.H{"name": "x", "trigger_type": "alert"}},
		}},
		{"training-mgmt", func(r *gin.Engine) {
			h := handlers.NewTrainingMgmtHandler(db.Pool())
			r.POST("/programs", h.CreateProgram)
			r.POST("/enrollments", h.EnrollUser)
		}, []write{
			{http.MethodPost, "/programs", gin.H{"name": "x", "program_type": "awareness"}},
			{http.MethodPost, "/enrollments", gin.H{"program_id": uuid.NewString(), "user_id": "u"}},
		}},
		{"hunting-campaign", func(r *gin.Engine) {
			h := handlers.NewHuntingCampaignHandler(db.Pool())
			r.POST("/campaigns", h.CreateCampaign)
			r.PUT("/campaigns/:id", h.UpdateCampaign)
			r.POST("/campaigns/:id/notes", h.AddNote)
		}, []write{
			{http.MethodPost, "/campaigns", gin.H{"name": "x", "hypothesis": "y"}},
			{http.MethodPut, "/campaigns/" + uuid.NewString(), gin.H{"status": "active"}},
			{http.MethodPost, "/campaigns/" + uuid.NewString() + "/notes", gin.H{"note": "n"}},
		}},
		{"compliance-remediation", func(r *gin.Engine) {
			h := handlers.NewComplianceRemediationHandler(db.Pool())
			r.POST("/rules", h.CreateRule)
			r.POST("/executions/:id/approve", h.ApproveExecution)
		}, []write{
			{http.MethodPost, "/rules", gin.H{"name": "x", "framework": "CIS"}},
			{http.MethodPost, "/executions/" + uuid.NewString() + "/approve", nil},
		}},
		{"security-dw", func(r *gin.Engine) {
			h := handlers.NewSecurityDWHandler(db.Pool())
			r.POST("/query", h.ExecuteQuery)
		}, []write{
			{http.MethodPost, "/query", gin.H{"query": "SELECT 1", "dataset": "alerts_db"}},
		}},
	}

	total := 0
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, _ := authRouter(t, db)
			tc.routes(r)
			for _, w := range tc.writes {
				total++
				rec := jsonReq(r, w.method, w.path, w.body)
				if rec.Code != http.StatusNotImplemented {
					t.Errorf("%s %s = %d, want 501\n%s", w.method, w.path, rec.Code, rec.Body.String())
					continue
				}
				var body map[string]any
				if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
					t.Errorf("%s %s: JSON ではありません: %s", w.method, w.path, rec.Body.String())
					continue
				}
				if body["unimplemented"] != true {
					t.Errorf("%s %s: unimplemented の印がありません。"+
						"**印が無いと、client は普通の失敗と区別できません**: %v", w.method, w.path, body)
				}
				if _, has := body["data"]; has {
					t.Errorf("%s %s: 501 なのに data を同梱しています。"+
						"**先に data を読む client には、以前と同じ「空」に見えます**: %v",
						w.method, w.path, body)
				}
			}
		})
	}

	// 走査が届いていること。**0件を検査して緑を返すのがいちばん高くつきます。**
	if total < 20 {
		t.Errorf("書き込みを %d 本しか叩いていません（実測 20）。"+
			"表が縮んでいないか確かめてください", total)
	}
}
