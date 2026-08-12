package scheduler

// 脅威フィード取り込みの取得〜保存までを端から端まで通す。
//
// importFeed は取得先 URL を threat_feeds テーブルから読むため、httptest の
// サーバを指す行を投入すれば外部ネットワークに出ずに全経路を実行できる。
// 本番コードに手を入れずに済むので、そのままの実装を検証できる。

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func fetchTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping DB-backed importer tests")
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// seedFeed は httptest サーバを指すフィード行を 1 件登録する。
func seedFeed(t *testing.T, pool *pgxpool.Pool, name, url, format string) {
	t.Helper()
	ctx := context.Background()

	cleanup := func() { _, _ = pool.Exec(ctx, `DELETE FROM threat_feeds WHERE name = $1`, name) }
	cleanup()
	t.Cleanup(cleanup)

	if _, err := pool.Exec(ctx, `
		INSERT INTO threat_feeds (name, url, format, enabled)
		VALUES ($1, $2, $3, TRUE)`, name, url, format); err != nil {
		t.Fatalf("seed threat_feeds: %v", err)
	}
}

// cleanupIOCs は投入した IOC を消す。
func cleanupIOCs(t *testing.T, pool *pgxpool.Pool, source string) {
	t.Helper()
	ctx := context.Background()
	del := func() { _, _ = pool.Exec(ctx, `DELETE FROM threat_intel_iocs WHERE source = $1`, source) }
	del()
	t.Cleanup(del)
}

// TestImportAll_CSVFeedEndToEnd は CSV フィードを取得して IOC を保存するまでを通す。
func TestImportAll_CSVFeedEndToEnd(t *testing.T) {
	pool := fetchTestPool(t)
	ctx := context.Background()

	const feedName = "itest-csv-feed"
	body := "# コメント\n203.0.113.211,ip,high,C2\n203.0.113.212,ip,medium,scanner\n"

	var gotUserAgent string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUserAgent = r.Header.Get("User-Agent")
		w.Header().Set("Content-Type", "text/csv")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	seedFeed(t, pool, feedName, srv.URL, "csv")
	cleanupIOCs(t, pool, feedName)

	imp := NewThreatFeedImporter(pool, nil)
	imp.importAll(ctx)

	// 取得側: User-Agent を名乗ること (フィード提供元が要求することがある)。
	if gotUserAgent == "" {
		t.Error("User-Agent が送られていない")
	}

	// 保存側: 2 件が threat_intel_iocs に入ること。
	var n int
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM threat_intel_iocs WHERE source = $1`, feedName).Scan(&n); err != nil {
		t.Fatalf("件数確認: %v", err)
	}
	if n != 2 {
		t.Errorf("保存された IOC = %d 件, want 2", n)
	}

	// 深刻度が 1–10 スケールへ写っていること。
	var sev int
	if err := pool.QueryRow(ctx,
		`SELECT severity FROM threat_intel_iocs WHERE source = $1 AND value = '203.0.113.211'`,
		feedName).Scan(&sev); err != nil {
		t.Fatalf("severity 確認: %v", err)
	}
	if sev != 7 {
		t.Errorf("severity = %d, want 7 (\"high\")", sev)
	}
}

// TestImportAll_JSONFeedEndToEnd は JSON フィード経路。
func TestImportAll_JSONFeedEndToEnd(t *testing.T) {
	pool := fetchTestPool(t)
	ctx := context.Background()

	const feedName = "itest-json-feed"
	body := `[
		{"indicator":"203.0.113.213","type":"ip","severity":"critical","description":"apt"},
		{"value":"bad213.example.invalid","type":"domain","severity":"low"}
	]`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	seedFeed(t, pool, feedName, srv.URL, "json")
	cleanupIOCs(t, pool, feedName)

	NewThreatFeedImporter(pool, nil).importAll(ctx)

	var n int
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM threat_intel_iocs WHERE source = $1`, feedName).Scan(&n); err != nil {
		t.Fatalf("件数確認: %v", err)
	}
	if n != 2 {
		t.Errorf("保存された IOC = %d 件, want 2", n)
	}

	// "critical" は 9 に写る。
	var sev int
	if err := pool.QueryRow(ctx,
		`SELECT severity FROM threat_intel_iocs WHERE source = $1 AND value = '203.0.113.213'`,
		feedName).Scan(&sev); err != nil {
		t.Fatalf("severity 確認: %v", err)
	}
	if sev != 9 {
		t.Errorf("severity = %d, want 9 (\"critical\")", sev)
	}
}

// TestImportAll_STIXFeedCountsOnly は STIX 経路。件数だけ数えて保存はしない。
func TestImportAll_STIXFeedCountsOnly(t *testing.T) {
	pool := fetchTestPool(t)
	ctx := context.Background()

	const feedName = "itest-stix-feed"
	body := `{"type":"bundle","objects":[
		{"type":"indicator","pattern":"[ipv4-addr:value = '203.0.113.214']"},
		{"type":"malware","name":"x"}
	]}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	seedFeed(t, pool, feedName, srv.URL, "stix")
	cleanupIOCs(t, pool, feedName)

	NewThreatFeedImporter(pool, nil).importAll(ctx)

	// STIX は countSTIXIndicators を通るだけで upsert しない。
	var n int
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM threat_intel_iocs WHERE source = $1`, feedName).Scan(&n); err != nil {
		t.Fatalf("件数確認: %v", err)
	}
	if n != 0 {
		t.Errorf("STIX 経路で %d 件保存されている, want 0", n)
	}
}

// TestImportAll_HTTPErrorIsTolerated は取得失敗でパニックせず次へ進むこと。
func TestImportAll_HTTPErrorIsTolerated(t *testing.T) {
	pool := fetchTestPool(t)
	ctx := context.Background()

	const feedName = "itest-error-feed"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	seedFeed(t, pool, feedName, srv.URL, "csv")
	cleanupIOCs(t, pool, feedName)

	// 500 応答でも本文を読んでパースを試みるだけで、落ちないこと。
	NewThreatFeedImporter(pool, nil).importAll(ctx)
}

// TestImportAll_TAXIIFeedsAreSkipped は taxii21 が FeedScheduler の担当であり
// このインポータでは取得しないことを確認する。二重取得の防止。
func TestImportAll_TAXIIFeedsAreSkipped(t *testing.T) {
	pool := fetchTestPool(t)
	ctx := context.Background()

	const feedName = "itest-taxii-feed"
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		_, _ = w.Write([]byte("203.0.113.215,ip,high,x\n"))
	}))
	t.Cleanup(srv.Close)

	cleanup := func() { _, _ = pool.Exec(ctx, `DELETE FROM threat_feeds WHERE name = $1`, feedName) }
	cleanup()
	t.Cleanup(cleanup)
	if _, err := pool.Exec(ctx, `
		INSERT INTO threat_feeds (name, url, format, source_format, enabled)
		VALUES ($1, $2, 'csv', 'taxii21', TRUE)`, feedName, srv.URL); err != nil {
		t.Fatalf("seed threat_feeds: %v", err)
	}

	NewThreatFeedImporter(pool, nil).importAll(ctx)

	if hits != 0 {
		t.Errorf("taxii21 フィードを %d 回取得している, want 0 (FeedScheduler の担当)", hits)
	}
}
