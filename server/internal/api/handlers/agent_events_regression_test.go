package handlers_test

// 存在しないテーブル `agent_events` を読んでいた経路の再発防止。
//
// テレメトリの実表は `events` (migration 002 の hypertable) で、列は
// event_id / agent_id / event_type / time / raw_data。
// `agent_events` というテーブルはスキーマのどこにも作られていない
// (migrations/ に CREATE が 1 つも無い)。
//
// これらのクエリは実 DB で必ず
//
//	ERROR:  relation "agent_events" does not exist
//
// で失敗するが、いずれも `if err == nil` で握りつぶしていたため、
// ネットワーク/ファイル/認証の統計も UEBA も、画面上は常に 0 件だった。
//
// ここでは実 DB に events を投入し、各エンドポイントが投入分を数え上げる
// ことを確認する。テーブル名・列名を誤ると SQL が落ちて 0 に戻るので、
// この件数アサートがそのまま回帰検出になる。

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/edr-platform/server/internal/api/handlers"
	"github.com/edr-platform/server/internal/store"
)

// seedAgentAndEvents はエージェント 1 台と、その名義の events を投入する。
func seedAgentAndEvents(t *testing.T, pool *pgxpool.Pool, tag, eventType string, n int, rawData string) (string, string) {
	t.Helper()
	ctx := context.Background()

	hostname := "agentev-" + tag
	var agentID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO agents (hostname, os_type, status, last_seen, enrolled_at)
		 VALUES ($1, 'linux', 'online', NOW(), NOW()) RETURNING id::text`,
		hostname).Scan(&agentID); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM agents WHERE id = $1`, agentID) })

	cleanup := func() { _, _ = pool.Exec(ctx, `DELETE FROM events WHERE agent_id = $1`, agentID) }
	cleanup()
	t.Cleanup(cleanup)

	if _, err := pool.Exec(ctx, `
		INSERT INTO events (time, agent_id, event_type, raw_data)
		SELECT NOW() - (g || ' minutes')::INTERVAL, $1::uuid, $2, $3::jsonb
		FROM generate_series(1, $4) g`, agentID, eventType, rawData, n); err != nil {
		t.Fatalf("seed events: %v", err)
	}

	return agentID, hostname
}

// ── /api/v1/events/network-stats ─────────────────────────────────

func TestNetworkStats_CountsEvents(t *testing.T) {
	pool := testPool(t)
	agentID, hostname := seedAgentAndEvents(t, pool, "net", "network", 25,
		`{"dst_ip":"203.0.113.77","dst_port":"4444","protocol":"tcp"}`)

	h := handlers.NewEventHandler(pool)

	// agent_id 指定あり: $1(hours) + $2(agent) の 2 引数経路。
	code, resp := doJSON(t, http.MethodGet,
		"/api/v1/events/network-stats?hours=24&agent_id="+agentID, nil, h.NetworkStats)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %v)", code, resp)
	}
	if got := numField(t, resp, "total"); got != 25 {
		t.Errorf("total = %v, want 25", got)
	}
	if !responseContains(resp, "203.0.113.77") {
		t.Errorf("宛先 IP 集計が空: %v", resp)
	}
	if !responseContains(resp, "4444") {
		t.Errorf("宛先ポート集計が空: %v", resp)
	}

	// agent_id 指定なし: $1 のみの経路。以前は hours を SQL に埋めつつ
	// args にも積んでいたため bind パラメータ数が合わず落ちていた。
	code, resp = doJSON(t, http.MethodGet,
		"/api/v1/events/network-stats?hours=24", nil, h.NetworkStats)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if got := numField(t, resp, "total"); got < 25 {
		t.Errorf("total = %v, want >= 25", got)
	}
	// 全体集計のときだけホスト別のトップが載る。
	if !responseContains(resp, hostname) {
		t.Errorf("トップエージェントに %q が出ていない: %v", hostname, resp)
	}
}

// ── /api/v1/events/file-stats ────────────────────────────────────

func TestFileStats_CountsEvents(t *testing.T) {
	pool := testPool(t)
	agentID, hostname := seedAgentAndEvents(t, pool, "file", "file", 18,
		`{"path":"/etc/agentev-secret.conf","operation":"write"}`)

	h := handlers.NewEventHandler(pool)

	code, resp := doJSON(t, http.MethodGet,
		"/api/v1/events/file-stats?hours=24&agent_id="+agentID, nil, h.FileStats)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %v)", code, resp)
	}
	if got := numField(t, resp, "total"); got != 18 {
		t.Errorf("total = %v, want 18", got)
	}
	if !responseContains(resp, "/etc/agentev-secret.conf") {
		t.Errorf("パス別集計が空: %v", resp)
	}

	code, resp = doJSON(t, http.MethodGet, "/api/v1/events/file-stats?hours=24", nil, h.FileStats)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if !responseContains(resp, hostname) {
		t.Errorf("トップエージェントに %q が出ていない: %v", hostname, resp)
	}
}

// ── /api/v1/events/auth-stats ────────────────────────────────────
//
// The auth/UEBA/graph fixtures below used to seed {"outcome":"failure"},
// {"image":...} and {"cmdline":...}. Ingestion writes none of those keys —
// normalizeEventData emits success (a JSON boolean), image_path and
// command_line — so the fixtures were built to match the readers rather than
// the producer, and the tests passed on a payload shape no agent has ever
// sent. They now seed what ingestion actually writes, which is the only form
// that makes them a regression test of anything.

func TestAuthStats_CountsEvents(t *testing.T) {
	pool := testPool(t)
	_, hostname := seedAgentAndEvents(t, pool, "auth", "auth", 12,
		`{"username":"agentev-user","success":false,"logon_type":"3"}`)

	h := handlers.NewEventHandler(pool)

	code, resp := doJSON(t, http.MethodGet, "/api/v1/events/auth-stats?hours=24", nil, h.AuthStats)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %v)", code, resp)
	}
	if got := numField(t, resp, "failure"); got < 12 {
		t.Errorf("failure = %v, want >= 12", got)
	}
	if !responseContains(resp, "agentev-user") {
		t.Errorf("ユーザ別集計に投入分が出ていない: %v", resp)
	}
	if !responseContains(resp, hostname) {
		t.Errorf("ホスト別集計に %q が出ていない: %v", hostname, resp)
	}
	// 時間帯別と直近一覧も同じテーブルを読む。
	if hourly, ok := resp["hourly"].([]any); !ok || len(hourly) == 0 {
		t.Errorf("時間帯別が空: %v", resp["hourly"])
	}
	if recent, ok := resp["recent"].([]any); !ok || len(recent) == 0 {
		t.Errorf("直近の認証イベントが空: %v", resp["recent"])
	}
}

// ── /api/v1/ueba/summary ─────────────────────────────────────────

func TestUEBASummary_CountsAuthAndProcessEvents(t *testing.T) {
	pool := testPool(t)
	_, hostname := seedAgentAndEvents(t, pool, "ueba", "auth", 9,
		`{"username":"agentev-ueba","success":false}`)

	// 「1 台でしか見ていないプロセス」の集計も同じテーブルを読む。
	// 除外パスに当たらない名前にする。
	procAgent, _ := seedAgentAndEvents(t, pool, "uebaproc", "process", 4,
		`{"image_path":"/opt/agentev/rare-binary"}`)
	_ = procAgent

	h := handlers.NewUEBAHandler(pool)
	code, resp := doJSON(t, http.MethodGet, "/api/v1/ueba/summary?hours=24", nil, h.Summary)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %v)", code, resp)
	}

	if !responseContains(resp, "agentev-ueba") {
		t.Errorf("ユーザ異常に投入分が出ていない: %v", resp)
	}
	if !responseContains(resp, hostname) {
		t.Errorf("エンティティ異常に %q が出ていない: %v", hostname, resp)
	}
	if !responseContains(resp, "/opt/agentev/rare-binary") {
		t.Errorf("希少プロセスに投入分が出ていない: %v", resp)
	}
}

// ── アラート調査グラフ ────────────────────────────────────────────

func TestAlertGraph_IncludesSurroundingEvents(t *testing.T) {
	db := testDB(t)
	pool := db.Pool()
	agentID, _ := seedAgentAndEvents(t, pool, "graph", "process", 5,
		`{"pid":"4242","image_path":"/tmp/agentev-graph","command_line":"-enc AAA"}`)

	ctx := context.Background()
	var alertID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO alerts (agent_id, severity, title, description, status, created_at)
		 VALUES ($1::uuid, 9, 'agentev-graph-alert', 'd', 'open', NOW()) RETURNING id::text`,
		agentID).Scan(&alertID); err != nil {
		t.Fatalf("seed alert: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM alerts WHERE id = $1`, alertID) })

	h := &handlers.AlertHandler{Store: store.NewAlertStore(db), Pool: pool}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/api/v1/alerts/:id/graph", h.Graph)

	w := jsonReq(r, http.MethodGet, "/api/v1/alerts/"+alertID+"/graph", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	if body := w.Body.String(); !strings.Contains(body, "/tmp/agentev-graph") {
		t.Errorf("調査グラフに前後のプロセスイベントが出ていない: %s", body)
	}
}
