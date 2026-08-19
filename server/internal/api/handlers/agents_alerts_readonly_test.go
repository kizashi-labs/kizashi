package handlers_test

// agents / alerts の読み取り系エンドポイントのスモークテスト。
//
// この 2 ファイルは合計 700 statements 以上が未カバーで、一覧・統計・履歴と
// いった主要な GET 経路が CI で一度も実行されていなかった。列名やプレース
// ホルダの誤りが混入しても気づけないため、実 DB に対して全経路を通す。

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/edr-platform/server/internal/api/handlers"
	"github.com/edr-platform/server/internal/store"
)

// noopPublisher は CommandStore が要求する Publish だけを満たすスタブ。
// 読み取り系テストではコマンドを発行しないので何もしない。
type noopPublisher struct{}

func (noopPublisher) Publish(string, []byte) error { return nil }

// callWithParams は URL パラメータ付きでハンドラを 1 本叩く。
func callWithParams(t *testing.T, target string, params gin.Params, h gin.HandlerFunc) (int, string) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, target, nil)
	c.Params = params
	stubAuthContext(c)
	h(c)
	return w.Code, w.Body.String()
}

// stubAuthContext puts what authMiddleware would put there.
//
// 多くのハンドラは `c.GetString("tenant_id")` を `WHERE tenant_id = $1::uuid`
// にそのまま渡します。空文字は uuid として解釈できないので、置き忘れると
// **ハンドラの中身に関係なく 500** になります。原因はハンドラではなく
// この文脈なので、ここに1つだけ置いて全員が使います。
func stubAuthContext(c *gin.Context) {
	c.Set("user_id", stubUserID)
	c.Set("tenant_id", stubTenantID)
	c.Set("role", "admin")
}

const (
	stubUserID   = "00000000-0000-0000-0000-000000000001"
	stubTenantID = "00000000-0000-0000-0000-000000000001"
)

// seedAgentAndAlert は参照先のあるエージェントとアラートを 1 件ずつ用意する。
func seedAgentAndAlert(t *testing.T, db *store.DB, agentID, alertID string) {
	t.Helper()
	ctx := context.Background()

	cleanup := func() {
		_, _ = db.Pool().Exec(ctx, `DELETE FROM alerts WHERE id=$1`, alertID)
		_, _ = db.Pool().Exec(ctx, `DELETE FROM agents WHERE id=$1`, agentID)
	}
	cleanup()
	t.Cleanup(cleanup)

	agentStore := store.NewAgentStore(db)
	if err := agentStore.UpsertAgent(ctx, &store.AgentRow{
		ID: agentID, Hostname: "readonly-itest-host", OSType: "linux",
		OSVersion: "22.04", AgentVersion: "1.0.0",
		IPAddresses: []string{"10.9.9.9"}, Status: "online",
	}); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}
	if _, err := db.Pool().Exec(ctx, `
		INSERT INTO alerts (id, agent_id, severity, status, title, description, created_at)
		VALUES ($1::uuid, $2::uuid, 7, 'open', 'readonly itest alert', 'desc', NOW())`,
		alertID, agentID); err != nil {
		t.Fatalf("seed alert: %v", err)
	}
}

// ── agents の読み取り系 ──────────────────────────────────────────

func TestAgentHandler_ReadOnlyEndpoints(t *testing.T) {
	db := testDB(t)
	const agentID = "d5d5d5d5-0000-4000-8000-000000000001"
	const alertID = "d5d5d5d5-0000-4000-8000-0000000000a1"
	seedAgentAndAlert(t, db, agentID, alertID)

	// 読み取り経路では Commander を使わないが、nil だと nil ポインタ参照に
	// なりうるので何もしない publisher を渡しておく。
	h := handlers.NewAgentHandler(store.NewAgentStore(db), store.NewCommandStore(db, noopPublisher{}))
	idParam := gin.Params{{Key: "id", Value: agentID}}

	cases := []struct {
		name   string
		target string
		params gin.Params
		fn     gin.HandlerFunc
	}{
		{"GetProcesses", "/api/v1/agents/" + agentID + "/processes", idParam, h.GetProcesses},
		{"GetProcessStats", "/api/v1/agents/" + agentID + "/process-stats", idParam, h.GetProcessStats},
		{"GetResponseHistory", "/api/v1/agents/" + agentID + "/response-history", idParam, h.GetResponseHistory},
		{"RiskScore", "/api/v1/agents/" + agentID + "/risk-score", idParam, h.RiskScore},
		{"ProcessTree", "/api/v1/agents/" + agentID + "/process-tree", idParam, h.ProcessTree},
		{"ListGroups", "/api/v1/agent-groups", nil, h.ListGroups},
		{"AnomalyBoard", "/api/v1/agents-anomaly-board", nil, h.AnomalyBoard},
	}
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

// ── alerts の読み取り系 ──────────────────────────────────────────

func TestAlertHandler_ReadOnlyEndpoints(t *testing.T) {
	db := testDB(t)
	const agentID = "d5d5d5d5-0000-4000-8000-000000000002"
	const alertID = "d5d5d5d5-0000-4000-8000-0000000000a2"
	seedAgentAndAlert(t, db, agentID, alertID)

	h := handlers.NewAlertHandler(store.NewAlertStore(db), store.NewAgentStore(db))
	h.Pool = db.Pool()
	idParam := gin.Params{{Key: "id", Value: alertID}}

	cases := []struct {
		name   string
		target string
		params gin.Params
		fn     gin.HandlerFunc
	}{
		{"List", "/api/v1/alerts?page=1&per_page=20", nil, h.List},
		{"Stats", "/api/v1/alerts/stats", nil, h.Stats},
		{"StatusHistory", "/api/v1/alerts/" + alertID + "/status-history", idParam, h.StatusHistory},
		{"Related", "/api/v1/alerts/" + alertID + "/related", idParam, h.Related},
		{"ListComments", "/api/v1/alerts/" + alertID + "/comments", idParam, h.ListComments},
		{"Graph", "/api/v1/alerts/" + alertID + "/graph", idParam, h.Graph},
	}
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

// TestAlertHandler_ListFiltersBySeverity は一覧のフィルタが効くことを見る。
// 一覧が常に全件返る実装でもスモークテストは通ってしまうため、
// 絞り込みが実際に効くかは別途確認する。
//
// severity は「以上」を意味する下限フィルタ (store 側で al.severity >= $n)、
// 上限は severity_max。両方の境界を投入した severity=7 のアラートで確かめる。
func TestAlertHandler_ListFiltersBySeverity(t *testing.T) {
	db := testDB(t)
	const agentID = "d5d5d5d5-0000-4000-8000-000000000003"
	const alertID = "d5d5d5d5-0000-4000-8000-0000000000a3"
	seedAgentAndAlert(t, db, agentID, alertID) // severity 7 のアラートが 1 件

	h := handlers.NewAlertHandler(store.NewAlertStore(db), store.NewAgentStore(db))
	h.Pool = db.Pool()

	countFor := func(query string) int {
		t.Helper()
		code, body := callWithParams(t, "/api/v1/alerts?"+query, nil, h.List)
		if code != http.StatusOK {
			t.Fatalf("%s: status = %d, want 200", query, code)
		}
		var resp struct {
			Data []struct {
				ID string `json:"id"`
			} `json:"data"`
		}
		if err := json.Unmarshal([]byte(body), &resp); err != nil {
			t.Fatalf("%s: invalid JSON: %v", query, err)
		}
		var n int
		for _, a := range resp.Data {
			if a.ID == alertID {
				n++
			}
		}
		return n
	}

	// 下限 7 は含む、下限 8 は除外する。
	if got := countFor("severity=7&per_page=100"); got != 1 {
		t.Errorf("severity>=7 で投入したアラートが %d 件 (want 1)", got)
	}
	if got := countFor("severity=8&per_page=100"); got != 0 {
		t.Errorf("severity>=8 に severity=7 のアラートが %d 件混ざっている (want 0)", got)
	}

	// 上限 7 は含む、上限 3 は除外する。
	if got := countFor("severity_max=7&per_page=100"); got != 1 {
		t.Errorf("severity<=7 で投入したアラートが %d 件 (want 1)", got)
	}
	if got := countFor("severity_max=3&per_page=100"); got != 0 {
		t.Errorf("severity<=3 に severity=7 のアラートが %d 件混ざっている (want 0)", got)
	}
}
