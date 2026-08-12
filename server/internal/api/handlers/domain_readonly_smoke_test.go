package handlers_test

// UEBA / パッチ / サンドボックス / フィッシング / メールセキュリティ /
// API セキュリティ / インシデントの読み取り系スモークテスト。
//
// いずれも実 DB に対して一度も実行されていなかった経路。列名やプレース
// ホルダの誤りが混入しても気づけないため、まず全経路を通す。

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/edr-platform/server/internal/api/handlers"
	"github.com/edr-platform/server/internal/store"
)

// readOnlyCase は「GET して 200 と JSON が返る」ことだけを見るケース。
type readOnlyCase struct {
	name   string
	target string
	params gin.Params
	fn     gin.HandlerFunc
}

func runReadOnlyCases(t *testing.T, cases []readOnlyCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, body := callWithParams(t, tc.target, tc.params, tc.fn)
			if code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (body: %s)", code, truncate(body, 400))
			}
			var resp any
			if err := json.Unmarshal([]byte(body), &resp); err != nil {
				t.Errorf("invalid JSON: %v (body: %s)", err, truncate(body, 200))
			}
		})
	}
}

// ── UEBA ─────────────────────────────────────────────────────────

func TestUEBAHandler_ReadOnlyEndpoints(t *testing.T) {
	pool := testPool(t)
	h := handlers.NewUEBAHandler(pool)

	runReadOnlyCases(t, []readOnlyCase{
		{"ListAnomalies", "/api/v1/ueba/anomalies?limit=20", nil, h.ListAnomalies},
		{"ListBaselines", "/api/v1/ueba/baselines", nil, h.ListBaselines},
		{"GetStats", "/api/v1/ueba/stats", nil, h.GetStats},
		{"ListUsers", "/api/v1/ueba/users", nil, h.ListUsers},
	})
}

// ── パッチ管理 ───────────────────────────────────────────────────

func TestPatchHandler_ReadOnlyEndpoints(t *testing.T) {
	pool := testPool(t)
	h := handlers.NewPatchHandler(pool, nil)

	runReadOnlyCases(t, []readOnlyCase{
		{"ListDeployments", "/api/v1/patches/deployments", nil, h.ListDeployments},
		{"GetStats", "/api/v1/patches/stats", nil, h.GetStats},
	})
}

// ── サンドボックス ───────────────────────────────────────────────

func TestSandboxHandler_ReadOnlyEndpoints(t *testing.T) {
	pool := testPool(t)
	h := handlers.NewSandboxHandler(pool)

	runReadOnlyCases(t, []readOnlyCase{
		{"ListSubmissions", "/api/v1/sandbox/submissions", nil, h.ListSubmissions},
		{"GetStats", "/api/v1/sandbox/stats", nil, h.GetStats},
	})
}

// ── フィッシング ─────────────────────────────────────────────────

func TestPhishingHandler_ReadOnlyEndpoints(t *testing.T) {
	pool := testPool(t)
	h := handlers.NewPhishingHandler(pool)

	runReadOnlyCases(t, []readOnlyCase{
		{"ListCampaigns", "/api/v1/phishing/campaigns", nil, h.ListCampaigns},
		{"GetStats", "/api/v1/phishing/stats", nil, h.GetStats},
		{"ListTemplates", "/api/v1/phishing/templates", nil, h.ListTemplates},
	})
}

// ── メールセキュリティ ───────────────────────────────────────────

func TestEmailSecurityHandler_ReadOnlyEndpoints(t *testing.T) {
	pool := testPool(t)
	h := handlers.NewEmailSecurityHandler(pool)

	runReadOnlyCases(t, []readOnlyCase{
		{"ListEvents", "/api/v1/email-security/events", nil, h.ListEvents},
		{"GetThreatTrend", "/api/v1/email-security/threat-trend", nil, h.GetThreatTrend},
		{"GetFrontendStats", "/api/v1/email-security/stats", nil, h.GetFrontendStats},
		{"ListThreats", "/api/v1/email-security/threats", nil, h.ListThreats},
		{"ListAttachments", "/api/v1/email-security/attachments", nil, h.ListAttachments},
		{"ListURLScans", "/api/v1/email-security/url-scans", nil, h.ListURLScans},
	})
}

// ── API セキュリティ ─────────────────────────────────────────────

func TestAPISecurityHandler_ReadOnlyEndpoints(t *testing.T) {
	pool := testPool(t)
	h := handlers.NewAPISecurityHandler(pool)

	runReadOnlyCases(t, []readOnlyCase{
		{"ListScans", "/api/v1/api-security/scans", nil, h.ListScans},
		{"ListEndpoints", "/api/v1/api-security/endpoints", nil, h.ListEndpoints},
		{"ListVulnerabilities", "/api/v1/api-security/vulnerabilities", nil, h.ListVulnerabilities},
		{"ListEvents", "/api/v1/api-security/events", nil, h.ListEvents},
	})
}

// ── インシデント ─────────────────────────────────────────────────

func TestIncidentHandler_List(t *testing.T) {
	db := testDB(t)
	h := handlers.NewIncidentHandler(store.NewIncidentStore(db))

	runReadOnlyCases(t, []readOnlyCase{
		{"List", "/api/v1/incidents?page=1&per_page=20", nil, h.List},
	})
}

// ── events の残る読み取り経路 ────────────────────────────────────

func TestEventHandler_RemainingReadOnlyEndpoints(t *testing.T) {
	pool := testPool(t)
	h := handlers.NewEventHandler(pool)

	const agentID = "d9d9d9d9-0000-4000-8000-000000000001"
	agentParam := gin.Params{{Key: "id", Value: agentID}}

	runReadOnlyCases(t, []readOnlyCase{
		{"Timeline", "/api/v1/events/timeline?hours=24", nil, h.Timeline},
		{"ListDNS", "/api/v1/events/dns", nil, h.ListDNS},
		{"ListByAgent", "/api/v1/agents/" + agentID + "/events", agentParam, h.ListByAgent},
		{"NetworkStats", "/api/v1/events/network-stats", nil, h.NetworkStats},
		{"FileStats", "/api/v1/events/file-stats", nil, h.FileStats},
		{"AuthStats", "/api/v1/events/auth-stats", nil, h.AuthStats},
		{"AgentTimeline", "/api/v1/agents/" + agentID + "/timeline", agentParam, h.AgentTimeline},
	})
}

// TestEventHandler_Search は JSON ボディを取る POST 経路。
func TestEventHandler_Search(t *testing.T) {
	pool := testPool(t)
	h := handlers.NewEventHandler(pool)

	gin.SetMode(gin.TestMode)

	t.Run("正常なボディ", func(t *testing.T) {
		body, _ := json.Marshal(map[string]any{
			"query": "powershell", "page": 1, "per_page": 20,
		})
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/events/search", bytes.NewReader(body))
		c.Request.Header.Set("Content-Type", "application/json")
		h.Search(c)

		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body: %s)", w.Code, truncate(w.Body.String(), 300))
		}
	})

	t.Run("不正なボディは 400", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/events/search",
			bytes.NewReader([]byte("{not json")))
		c.Request.Header.Set("Content-Type", "application/json")
		h.Search(c)

		if w.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", w.Code)
		}
	})
}
