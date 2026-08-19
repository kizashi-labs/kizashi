package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/edr-platform/server/internal/sandbox"
	"github.com/edr-platform/server/internal/threatintel"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Enriching an indicator that IS in the IOC table answered that it was not.
//
// Measured before this change, for a domain added the way store/ioc.go adds
// one — type, value, description, severity, is_active — and nothing else:
//
//	POST /api/v1/ioc/enrich  {"value":"..."}
//	  -> {"found":false,"ioc_type":"","threat_level":0,"description":"", ...}
//	rows actually present in ioc_entries: 1
//
// Two causes, both in the scan. Enrich read ioc_type / threat_level / enabled
// — the nullable, defaulted and never-updated halves of ioc_entries' three
// duplicated column pairs — and ioc_type is NULL for every indicator added by
// hand or imported over TAXII or STIX. And first_seen and last_seen are
// nullable, unset by those same writers, and were scanned into time.Time. Any
// of those NULLs fails the Scan, and the handler treated a scan failure as
// "no such indicator".
//
// BulkEnrich already read the right columns and still failed, purely on the
// timestamps: the same value returned found=false one at a time AND in bulk,
// for two different reasons.
//
// This is the lookup a SOC uses to ask whether an indicator has been seen
// before. It answered no about indicators the team had entered themselves.

func iocLookupPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping DB integration tests")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// seedManualIOC inserts an indicator exactly as store/ioc.go AddIOC does:
// no ioc_type, no first_seen, no last_seen.
func seedManualIOC(t *testing.T, pool *pgxpool.Pool, value, desc string, severity int) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO ioc_entries (type, value, description, severity, is_active)
		VALUES ('domain', $1, $2, $3, TRUE)`, value, desc, severity); err != nil {
		t.Fatalf("seed %q: %v", value, err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM ioc_entries WHERE value=$1`, value)
	})
}

// enrich calls the single-value lookup.
func enrich(t *testing.T, h *IOCEnrichmentHandler, value string) map[string]interface{} {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/ioc/enrich",
		strings.NewReader(`{"value":"`+value+`"}`))
	c.Request.Header.Set("Content-Type", "application/json")
	h.Enrich(c)

	var decoded map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("enrich response is not JSON: %v (%s)", err, w.Body.String())
	}
	return decoded
}

// The lookup must find an indicator that is in the table.
func TestEnrichingAManuallyAddedIOCFindsIt(t *testing.T) {
	pool := iocLookupPool(t)
	h := &IOCEnrichmentHandler{pool: pool}
	seedManualIOC(t, pool, "enrich-known.example", "known C2 panel", 9)

	got := enrich(t, h, "enrich-known.example")
	if got["found"] != true {
		t.Fatalf("テーブルに存在する指標が found=false で返りました: %v", got)
	}
	if got["ioc_type"] != "domain" {
		t.Errorf("ioc_type が %v、期待は domain", got["ioc_type"])
	}
	if got["threat_level"] != float64(9) {
		t.Errorf("threat_level が %v、期待は 9 — "+
			"フィードが設定した severity ではなく threat_level の既定値を読んでいます", got["threat_level"])
	}
	if got["description"] != "known C2 panel" {
		t.Errorf("description が %v", got["description"])
	}
}

// An indicator genuinely absent must still be reported as not found.
func TestEnrichingAnUnknownValueIsNotFound(t *testing.T) {
	pool := iocLookupPool(t)
	h := &IOCEnrichmentHandler{pool: pool}

	got := enrich(t, h, "enrich-never-seen.example")
	if got["found"] != false {
		t.Errorf("未登録の値が found=true で返りました: %v", got)
	}
}

// A deactivated indicator must not be reported as a current hit.
func TestEnrichingADeactivatedIOCIsNotFound(t *testing.T) {
	pool := iocLookupPool(t)
	h := &IOCEnrichmentHandler{pool: pool}

	if _, err := pool.Exec(context.Background(), `
		INSERT INTO ioc_entries (type, value, description, severity, is_active)
		VALUES ('domain', 'enrich-off.example', 'retired', 9, FALSE)`); err != nil {
		t.Fatalf("seed: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM ioc_entries WHERE value='enrich-off.example'`)
	})

	got := enrich(t, h, "enrich-off.example")
	if got["found"] != false {
		t.Errorf("無効化した指標がヒットとして返りました: %v", got)
	}
}

// The single and bulk lookups must agree about the same value. They did not:
// both said not-found, for different reasons.
func TestSingleAndBulkEnrichmentAgree(t *testing.T) {
	pool := iocLookupPool(t)
	h := &IOCEnrichmentHandler{pool: pool}
	seedManualIOC(t, pool, "enrich-both.example", "seen in both", 7)

	single := enrich(t, h, "enrich-both.example")

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/ioc/enrich/bulk",
		strings.NewReader(`{"items":[{"value":"enrich-both.example"}]}`))
	c.Request.Header.Set("Content-Type", "application/json")
	h.BulkEnrich(c)

	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("bulk response: %v", err)
	}
	list, _ := body["results"].([]interface{})
	if len(list) != 1 {
		t.Fatalf("bulk returned %d results", len(list))
	}
	bulk, _ := list[0].(map[string]interface{})

	if single["found"] != bulk["found"] {
		t.Errorf("単体照会と一括照会で結果が食い違います: single=%v bulk=%v",
			single["found"], bulk["found"])
	}
	if bulk["found"] != true {
		t.Errorf("一括照会が既知の指標を見つけられません: %v", bulk)
	}
	if single["threat_level"] != bulk["threat_level"] {
		t.Errorf("深刻度が食い違います: single=%v bulk=%v",
			single["threat_level"], bulk["threat_level"])
	}
}

// Search must return an indicator with no timestamps, and one such row must not
// truncate the rest — pgx ends iteration on a scan error.
func TestSearchReturnsIOCsWithNoTimestamps(t *testing.T) {
	pool := iocLookupPool(t)
	h := &IOCEnrichmentHandler{pool: pool}
	seedManualIOC(t, pool, "enrich-search-a.example", "first", 5)
	seedManualIOC(t, pool, "enrich-search-b.example", "second", 8)

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/ioc/search?q=enrich-search", nil)
	h.Search(c)

	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("search response: %v", err)
	}
	list, _ := body["results"].([]interface{})
	if len(list) != 2 {
		t.Fatalf("検索が %d 件を返しました (期待 2)。"+
			"タイムスタンプ未設定の1件が以降を打ち切っている可能性があります: %v", len(list), body)
	}
	// Ordered by severity, so the more severe one leads.
	first, _ := list[0].(map[string]interface{})
	if first["threat_level"] != float64(8) {
		t.Errorf("検索結果が深刻度順ではありません: %v", first["threat_level"])
	}
	for _, item := range list {
		hit, _ := item.(map[string]interface{})
		if hit["ioc_type"] != "domain" {
			t.Errorf("検索結果の ioc_type が %v", hit["ioc_type"])
		}
		// first_seen was never recorded for these, so the row's creation time
		// stands in — the same fallback the single and bulk lookups use.
		if _, present := hit["first_seen"]; !present {
			t.Errorf("検索結果に first_seen がありません。"+
				"first_seen 未設定なら created_at を返す必要があります: %v", hit)
		}
	}
}

// Sandbox enrichment must not report an indicator an analyst switched off.
func TestSandboxIOCHitsRespectDeactivation(t *testing.T) {
	pool := iocLookupPool(t)
	ctx := context.Background()

	if _, err := pool.Exec(ctx, `
		INSERT INTO ioc_entries (type, value, description, severity, is_active)
		VALUES ('domain', 'enrich-sandbox-on', 'live', 9, TRUE),
		       ('domain', 'enrich-sandbox-off', 'retired', 9, FALSE)`); err != nil {
		t.Fatalf("seed: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM ioc_entries WHERE value LIKE 'enrich-sandbox-%'`)
	})

	h := &SandboxHandler{pool: pool}
	hits, err := h.correlateIOCs(ctx, sandbox.StaticVerdict{
		Domains: []string{"enrich-sandbox-on", "enrich-sandbox-off"},
	})
	if err != nil {
		t.Fatalf("correlateIOCs: %v", err)
	}

	joined := strings.Join(hits, ",")
	if !strings.Contains(joined, "enrich-sandbox-on") {
		t.Errorf("有効な指標がヒットしていません: %v", hits)
	}
	if strings.Contains(joined, "enrich-sandbox-off") {
		t.Errorf("無効化した指標がヒットとして返りました: %v", hits)
	}
}

// When first_seen was never recorded, the lookup reports when the row was
// created rather than nothing — an indicator the team has held since March
// should not read as having no history.
func TestAMissingFirstSeenFallsBackToWhenTheRowWasCreated(t *testing.T) {
	pool := iocLookupPool(t)
	h := &IOCEnrichmentHandler{pool: pool}
	ctx := context.Background()

	if _, err := pool.Exec(ctx, `
		INSERT INTO ioc_entries (type, value, description, severity, is_active, created_at)
		VALUES ('domain','enrich-created.example','no timestamps',6,TRUE,
		        TIMESTAMPTZ '2026-03-01 12:00:00+00')`); err != nil {
		t.Fatalf("seed: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM ioc_entries WHERE value='enrich-created.example'`)
	})

	got := enrich(t, h, "enrich-created.example")
	if got["found"] != true {
		t.Fatalf("見つかりません: %v", got)
	}
	first, _ := got["first_seen"].(string)
	if !strings.HasPrefix(first, "2026-03-01") {
		t.Errorf("first_seen が %q。first_seen 未設定なら created_at を返す必要があります", first)
	}
	last, _ := got["last_seen"].(string)
	if !strings.HasPrefix(last, "2026-03-01") {
		t.Errorf("last_seen が %q", last)
	}
}

// With no timestamp of any kind on record, the lookup must say nothing rather
// than invent one. created_at is nullable too, so this is reachable.
func TestAnIOCWithNoTimestampsAtAllReportsNone(t *testing.T) {
	pool := iocLookupPool(t)
	h := &IOCEnrichmentHandler{pool: pool}
	ctx := context.Background()

	if _, err := pool.Exec(ctx, `
		INSERT INTO ioc_entries (type, value, description, severity, is_active, created_at)
		VALUES ('domain','enrich-notime.example','nothing at all',6,TRUE,NULL)`); err != nil {
		t.Fatalf("seed: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM ioc_entries WHERE value='enrich-notime.example'`)
	})

	got := enrich(t, h, "enrich-notime.example")
	if got["found"] != true {
		t.Fatalf("タイムスタンプが無いだけの指標が見つかりません: %v", got)
	}
	// omitempty drops the zero time, so the field must be absent — not a
	// plausible-looking timestamp standing in for one nobody recorded.
	if v, present := got["first_seen"]; present {
		t.Errorf("記録の無い first_seen に %v が入りました", v)
	}
	if v, present := got["last_seen"]; present {
		t.Errorf("記録の無い last_seen に %v が入りました", v)
	}
}

// The bulk lookup reports the same fallback as the single one.
func TestBulkEnrichmentReportsTheSameTimestamps(t *testing.T) {
	pool := iocLookupPool(t)
	h := &IOCEnrichmentHandler{pool: pool}
	ctx := context.Background()

	if _, err := pool.Exec(ctx, `
		INSERT INTO ioc_entries (type, value, description, severity, is_active, created_at)
		VALUES ('domain','enrich-bulktime.example','bulk',6,TRUE,
		        TIMESTAMPTZ '2026-02-02 09:00:00+00')`); err != nil {
		t.Fatalf("seed: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM ioc_entries WHERE value='enrich-bulktime.example'`)
	})

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/ioc/enrich/bulk",
		strings.NewReader(`{"items":[{"value":"enrich-bulktime.example"}]}`))
	c.Request.Header.Set("Content-Type", "application/json")
	h.BulkEnrich(c)

	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("bulk: %v", err)
	}
	list, _ := body["results"].([]interface{})
	if len(list) != 1 {
		t.Fatalf("bulk returned %d", len(list))
	}
	hit, _ := list[0].(map[string]interface{})
	first, _ := hit["first_seen"].(string)
	if !strings.HasPrefix(first, "2026-02-02") {
		t.Errorf("一括照会の first_seen が %q、created_at を返す必要があります", first)
	}
}

// Search must exclude a deactivated indicator, like every other read.
func TestSearchExcludesDeactivatedIOCs(t *testing.T) {
	pool := iocLookupPool(t)
	h := &IOCEnrichmentHandler{pool: pool}
	ctx := context.Background()

	if _, err := pool.Exec(ctx, `
		INSERT INTO ioc_entries (type, value, description, severity, is_active)
		VALUES ('domain','enrich-srch-on.example','live',5,TRUE),
		       ('domain','enrich-srch-off.example','retired',9,FALSE)`); err != nil {
		t.Fatalf("seed: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM ioc_entries WHERE value LIKE 'enrich-srch-%'`)
	})

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/ioc/search?q=enrich-srch", nil)
	h.Search(c)

	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("search: %v", err)
	}
	list, _ := body["results"].([]interface{})
	values := []string{}
	for _, item := range list {
		hit, _ := item.(map[string]interface{})
		v, _ := hit["value"].(string)
		values = append(values, v)
	}
	joined := strings.Join(values, ",")
	if !strings.Contains(joined, "enrich-srch-on.example") {
		t.Errorf("有効な指標が検索結果にありません: %v", values)
	}
	if strings.Contains(joined, "enrich-srch-off.example") {
		t.Errorf("無効化した指標が検索結果に含まれています: %v", values)
	}
}

// The enrichment cache writes back to ioc_entries, and it was the one writer
// keeping threat_level alive. Migration 379 dropped that column, so a revert
// fails with 42703 — but only when a live reputation lookup actually runs,
// which nothing tested. This drives it directly.
func TestTheEnrichmentCacheWritesTheCurrentColumns(t *testing.T) {
	pool := iocLookupPool(t)
	h := &IOCEnrichmentHandler{pool: pool}
	ctx := context.Background()

	const value = "cache-live.example"
	_, _ = pool.Exec(ctx, `DELETE FROM ioc_entries WHERE value=$1`, value)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM ioc_entries WHERE value=$1`, value)
	})

	h.cacheLive(ctx, value, "domain", 8, []string{"c2"}, threatintel.LiveResult{
		Found: true, Score: 80, Verdict: "malicious", Malicious: 12,
		Sources: []string{"unit-test"},
	})

	var severity int
	var active bool
	var typ string
	if err := pool.QueryRow(ctx, `
		SELECT type, severity, is_active FROM ioc_entries WHERE value=$1`,
		value).Scan(&typ, &severity, &active); err != nil {
		t.Fatalf("キャッシュされた指標が読み出せません: %v", err)
	}
	if typ != "domain" {
		t.Errorf("type が %q", typ)
	}
	if !active {
		t.Error("キャッシュされた指標が is_active=false です")
	}
	if severity != 8 {
		t.Errorf("severity が %d、期待は 8 — 計算した脅威度が severity に入る必要があります", severity)
	}
}

// severity's CHECK is 1..10 and the value the cache computes is live.Score/10,
// which is 0 for a low score. Without a clamp the write fails outright and the
// indicator is silently not cached.
func TestTheEnrichmentCacheClampsToTheSeverityRange(t *testing.T) {
	pool := iocLookupPool(t)
	h := &IOCEnrichmentHandler{pool: pool}
	ctx := context.Background()

	for _, tc := range []struct {
		name     string
		value    string
		computed int
		want     int
	}{
		{"below the minimum", "cache-zero.example", 0, 1},
		{"above the maximum", "cache-high.example", 40, 10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _ = pool.Exec(ctx, `DELETE FROM ioc_entries WHERE value=$1`, tc.value)
			t.Cleanup(func() {
				_, _ = pool.Exec(context.Background(), `DELETE FROM ioc_entries WHERE value=$1`, tc.value)
			})

			h.cacheLive(ctx, tc.value, "domain", tc.computed, []string{}, threatintel.LiveResult{
				Found: true, Score: 50, Verdict: "suspicious", Sources: []string{"unit-test"},
			})

			var severity int
			if err := pool.QueryRow(ctx,
				`SELECT severity FROM ioc_entries WHERE value=$1`, tc.value).Scan(&severity); err != nil {
				t.Fatalf("範囲外の値でキャッシュが書き込まれませんでした: %v", err)
			}
			if severity != tc.want {
				t.Errorf("severity が %d、期待は %d", severity, tc.want)
			}
		})
	}
}
