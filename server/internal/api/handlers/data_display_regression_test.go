package handlers_test

// 「データが表示されない」系バグの再発防止。
//
// events の実際の時刻列は `time`、種別列は `event_type`、ペイロードは `raw_data`
// (migration 002)。これらを `timestamp` / `type` / `created_at` / `event_data` と
// 取り違えたクエリが 4 箇所にあり、いずれもエラーを握りつぶしていたため
// 「画面上は 0 件」としか見えなかった。
//
// ここでは実 DB に events を投入し、各エンドポイントが投入分を数え上げることを
// 確認する。列名を誤ると SQL が落ちて 0 のままになるので、この差分アサートが
// そのまま回帰検出になる。

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/edr-platform/server/internal/api/handlers"
	"github.com/edr-platform/server/internal/store"
)

// seedTestEvents は agentID 名義の events を n 件投入し、後始末を登録する。
// 時刻は直近 n 分に散らすため、24 時間窓のクエリはすべて拾う。
func seedTestEvents(t *testing.T, pool *pgxpool.Pool, agentID, eventType string, n int, rawData string) {
	t.Helper()
	ctx := context.Background()

	cleanup := func() {
		_, _ = pool.Exec(ctx, `DELETE FROM events WHERE agent_id = $1`, agentID)
	}
	cleanup()
	t.Cleanup(cleanup)

	if _, err := pool.Exec(ctx, `
		INSERT INTO events (time, agent_id, event_type, raw_data)
		SELECT NOW() - (g || ' minutes')::INTERVAL, $1::uuid, $2, $3::jsonb
		FROM generate_series(1, $4) g`, agentID, eventType, rawData, n); err != nil {
		t.Fatalf("seed events: %v", err)
	}
}

// doJSON は 1 ハンドラを叩いて JSON を取り出す小さなヘルパ。
func doJSON(t *testing.T, method, target string, body []byte, h gin.HandlerFunc) (int, map[string]any) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	var req *http.Request
	if body == nil {
		req = httptest.NewRequest(method, target, nil)
	} else {
		req = httptest.NewRequest(method, target, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	}
	c.Request = req
	h(c)

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON response (status %d): %v\nbody: %s", w.Code, err, w.Body.String())
	}
	return w.Code, resp
}

// numField は JSON 数値を float64 として取り出す。
func numField(t *testing.T, resp map[string]any, key string) float64 {
	t.Helper()
	v, ok := resp[key]
	if !ok {
		t.Fatalf("レスポンスに %q が無い: %v", key, resp)
	}
	f, ok := v.(float64)
	if !ok {
		t.Fatalf("%q が数値でない: %T (%v)", key, v, v)
	}
	return f
}

// ── /api/v1/events 一覧 ──────────────────────────────────────────

func TestEventHandler_List_ReturnsSeededEvents(t *testing.T) {
	pool := testPool(t)
	const agentID = "e0e0e0e0-0000-4000-8000-000000000001"
	seedTestEvents(t, pool, agentID, "process", 12, `{"cmdline":"powershell -enc AAA"}`)

	h := handlers.NewEventHandler(pool)
	code, resp := doJSON(t, http.MethodGet,
		"/api/v1/events?agent_id="+agentID+"&per_page=50", nil, h.List)

	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %v)", code, resp)
	}
	if got := numField(t, resp, "total"); got != 12 {
		t.Errorf("total = %v, want 12", got)
	}
	if capped, _ := resp["total_capped"].(bool); capped {
		t.Error("total_capped = true, want false (12 件で打ち切られるはずがない)")
	}
	if more, _ := resp["has_more"].(bool); more {
		t.Error("has_more = true, want false (1 ページに収まる)")
	}
	data, ok := resp["data"].([]any)
	if !ok {
		t.Fatalf("data が配列でない: %T", resp["data"])
	}
	if len(data) != 12 {
		t.Fatalf("data の件数 = %d, want 12", len(data))
	}

	// 1 件目の形を見る。raw_data がそのまま JSON として載ること
	// (以前は存在しない列を読もうとして 500 になっていた)。
	first, ok := data[0].(map[string]any)
	if !ok {
		t.Fatalf("data[0] がオブジェクトでない: %T", data[0])
	}
	for _, k := range []string{"id", "agent_id", "event_type", "raw_data", "timestamp"} {
		if _, ok := first[k]; !ok {
			t.Errorf("data[0] に %q が無い: %v", k, first)
		}
	}
	if first["event_type"] != "process" {
		t.Errorf("event_type = %v, want process", first["event_type"])
	}
}

func TestEventHandler_List_PaginatesAndFilters(t *testing.T) {
	pool := testPool(t)
	const agentID = "e0e0e0e0-0000-4000-8000-000000000002"
	seedTestEvents(t, pool, agentID, "network", 30, `{"protocol":"TLS"}`)

	h := handlers.NewEventHandler(pool)

	// 2 ページ目 (per_page=10) は 10 件、has_more は true。
	code, resp := doJSON(t, http.MethodGet,
		"/api/v1/events?agent_id="+agentID+"&per_page=10&page=2", nil, h.List)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if got := numField(t, resp, "total"); got != 30 {
		t.Errorf("total = %v, want 30", got)
	}
	if got := numField(t, resp, "page"); got != 2 {
		t.Errorf("page = %v, want 2", got)
	}
	data, _ := resp["data"].([]any)
	if len(data) != 10 {
		t.Errorf("data の件数 = %d, want 10", len(data))
	}
	if more, _ := resp["has_more"].(bool); !more {
		t.Error("has_more = false, want true (30 件中 20 件目まで)")
	}

	// 種別フィルタが効かない (= 全件返る) と一覧の絞り込みが無意味になる。
	code, resp = doJSON(t, http.MethodGet,
		"/api/v1/events?agent_id="+agentID+"&type=process", nil, h.List)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if got := numField(t, resp, "total"); got != 0 {
		t.Errorf("type=process の total = %v, want 0 (投入したのは network のみ)", got)
	}

	// search は raw_data::text の ILIKE。ペイロード中の値で引ける。
	code, resp = doJSON(t, http.MethodGet,
		"/api/v1/events?agent_id="+agentID+"&search=TLS", nil, h.List)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if got := numField(t, resp, "total"); got != 30 {
		t.Errorf("search=TLS の total = %v, want 30", got)
	}
}

// ── /api/v1/network-traffic/stats ────────────────────────────────

func TestNetworkTrafficHandler_GetStats_CountsNetworkEvents(t *testing.T) {
	pool := testPool(t)
	const agentID = "e0e0e0e0-0000-4000-8000-000000000003"
	const proto = "TESTPROTO"

	h := handlers.NewNetworkTrafficHandler(pool)

	_, before := doJSON(t, http.MethodGet, "/api/v1/network-traffic/stats", nil, h.GetStats)
	baseFlows := numField(t, before, "total_flows")

	seedTestEvents(t, pool, agentID, "network", 40,
		fmt.Sprintf(`{"protocol":%q}`, proto))

	code, after := doJSON(t, http.MethodGet, "/api/v1/network-traffic/stats", nil, h.GetStats)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}

	// 誤った列 (type / created_at) を参照していた頃はクエリが常に落ち、
	// total_flows が 0 のまま動かなかった。
	gotFlows := numField(t, after, "total_flows")
	if gotFlows < baseFlows+40 {
		t.Errorf("total_flows = %v, want >= %v (40 件投入後)", gotFlows, baseFlows+40)
	}
	if bw := numField(t, after, "bandwidth_gb"); bw <= 0 {
		t.Errorf("bandwidth_gb = %v, want > 0 (total_flows から算出される)", bw)
	}

	// top_protocol は raw_data->>'protocol' から取る。events は他パッケージの
	// テストとも共有するため、投入分が実際に最多である場合のみ値を突き合わせる。
	var dbTop string
	err := pool.QueryRow(context.Background(), `
		SELECT COALESCE(raw_data->>'protocol', 'TCP')
		FROM events
		WHERE event_type='network' AND time > NOW()-INTERVAL '24h'
		GROUP BY 1 ORDER BY COUNT(*) DESC LIMIT 1`).Scan(&dbTop)
	if err != nil {
		t.Fatalf("最多プロトコルの確認クエリ: %v", err)
	}
	if dbTop != proto {
		t.Skipf("他テストの network イベントが優勢 (top=%q) のため突き合わせを省略", dbTop)
	}
	if after["top_protocol"] != proto {
		t.Errorf("top_protocol = %v, want %q (raw_data から取れていない)", after["top_protocol"], proto)
	}
}

// ── /api/v1/metrics/summary ──────────────────────────────────────

func TestMetricsHistoryHandler_GetSummary_CountsEvents(t *testing.T) {
	pool := testPool(t)
	const agentID = "e0e0e0e0-0000-4000-8000-000000000004"

	h := handlers.NewMetricsHistoryHandler(pool)

	_, before := doJSON(t, http.MethodGet, "/api/v1/metrics/summary", nil, h.GetSummary)
	baseCount := numField(t, before, "event_count")

	seedTestEvents(t, pool, agentID, "process", 25, `{"cmdline":"whoami"}`)

	code, after := doJSON(t, http.MethodGet, "/api/v1/metrics/summary", nil, h.GetSummary)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}

	// `WHERE timestamp >= $1` だった頃はこのクエリが常に落ち、event_count と
	// threat_detection_rate が 0 に固定されていた。
	got := numField(t, after, "event_count")
	if got < baseCount+25 {
		t.Errorf("event_count = %v, want >= %v (25 件投入後)", got, baseCount+25)
	}
	if _, ok := after["threat_detection_rate"]; !ok {
		t.Error("threat_detection_rate が返っていない")
	}
}

// ── /api/v1/rules/test ───────────────────────────────────────────

func TestRuleTestHandler_Test_CountsEventsInLookback(t *testing.T) {
	pool := testPool(t)
	const agentID = "e0e0e0e0-0000-4000-8000-000000000005"

	h := handlers.NewRuleTestHandler(pool)
	body, _ := json.Marshal(map[string]any{
		"rule_name":      "regression-probe",
		"condition":      "true",
		"lookback_hours": 24,
	})

	_, before := doJSON(t, http.MethodPost, "/api/v1/rules/test", body, h.Test)
	baseTotal := numField(t, before, "total_events_checked")

	seedTestEvents(t, pool, agentID, "process", 18, `{"cmdline":"net user"}`)

	code, after := doJSON(t, http.MethodPost, "/api/v1/rules/test", body, h.Test)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %v)", code, after)
	}

	// `WHERE timestamp >= ...` だった頃はルールテストの対象件数が常に 0 で、
	// 「ルールが何にもマッチしない」ように見えていた。
	got := numField(t, after, "total_events_checked")
	if got < baseTotal+18 {
		t.Errorf("total_events_checked = %v, want >= %v (18 件投入後)", got, baseTotal+18)
	}
}

// ── ダッシュボードのイベントタイムライン ─────────────────────────

// TestAlertHandler_Dashboard_EventTimelineHasBuckets は
// buildEventTimeline が時間バケットを返すことを見る。`date_trunc('hour', timestamp)`
// だった頃はクエリが毎回落ちて、タイムラインが常に空 (= グラフが 0 件) だった。
func TestAlertHandler_Dashboard_EventTimelineHasBuckets(t *testing.T) {
	db := testDB(t)
	pool := db.Pool()
	const agentID = "e0e0e0e0-0000-4000-8000-000000000006"

	// 直近 24h に process / file / network を散らす。
	for _, et := range []string{"process", "file", "network"} {
		if _, err := pool.Exec(context.Background(), `
			INSERT INTO events (time, agent_id, event_type, raw_data)
			SELECT NOW() - (g || ' hours')::INTERVAL, $1::uuid, $2, '{"src":"timeline-test"}'::jsonb
			FROM generate_series(1, 5) g`, agentID, et); err != nil {
			t.Fatalf("seed %s events: %v", et, err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM events WHERE agent_id = $1`, agentID)
	})

	h := handlers.NewAlertHandler(store.NewAlertStore(db), store.NewAgentStore(db))
	h.Pool = pool

	code, resp := doJSON(t, http.MethodGet, "/api/v1/dashboard", nil, h.Dashboard)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %v)", code, resp)
	}

	timeline, ok := resp["event_timeline"].([]any)
	if !ok {
		t.Fatalf("event_timeline が配列でない: %T (%v)", resp["event_timeline"], resp["event_timeline"])
	}
	if len(timeline) == 0 {
		t.Fatal("event_timeline が空。24h 以内に 15 件投入済みなのでバケットが立つはず")
	}

	// バケットの合計が投入分を下回らないこと (他テストのイベントも混ざりうるので下限で見る)。
	var total float64
	for _, b := range timeline {
		bucket, ok := b.(map[string]any)
		if !ok {
			t.Fatalf("バケットがオブジェクトでない: %T", b)
		}
		for _, k := range []string{"process_events", "file_events", "network_events"} {
			v, ok := bucket[k].(float64)
			if !ok {
				t.Fatalf("バケットに数値の %q が無い: %v", k, bucket)
			}
			total += v
		}
	}
	if total < 15 {
		t.Errorf("タイムライン上のイベント総数 = %v, want >= 15", total)
	}
}
