package scheduler

// ransomwatch 同期の取得〜保存。
//
// 取得先 URL は DarkWebScheduler.ransomwatchURL から読むので、httptest の
// サーバへ向ければ外部に出ずに全経路を通せる。

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// newSchedulerAgainst は指定 URL を向いたスケジューラを返す。
func newSchedulerAgainst(pool *pgxpool.Pool, url string) *DarkWebScheduler {
	s := NewDarkWebScheduler(pool, "", false)
	s.ransomwatchURL = url
	return s
}

// cleanupSites は投入したサイト行を消す。
func cleanupSites(t *testing.T, pool *pgxpool.Pool, groupNames ...string) {
	t.Helper()
	ctx := context.Background()
	del := func() {
		for _, g := range groupNames {
			_, _ = pool.Exec(ctx, `DELETE FROM darkweb_ransomware_sites WHERE group_name = $1`, g)
		}
		_, _ = pool.Exec(ctx, `DELETE FROM darkweb_ransomware_sites WHERE onion_url = '__cache__'`)
	}
	del()
	t.Cleanup(del)
}

// TestSyncRansomwatch_StoresSitesAndCache は .onion の登録とキャッシュ保存。
func TestSyncRansomwatch_StoresSitesAndCache(t *testing.T) {
	pool := darkwebTestPool(t)
	ctx := context.Background()
	cleanupSites(t, pool, "ITestGroupA", "ITestGroupB")

	body := `[
	  {"name":"ITestGroupA",
	   "locations":[{"fqdn":"itestgroupa-abcdef","available":true}],
	   "posts":[{"post_title":"victim one"}]},
	  {"name":"ITestGroupB",
	   "locations":[{"fqdn":"itestgroupb-ghijkl.onion","available":false},{"fqdn":""}],
	   "posts":[]}
	]`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	newSchedulerAgainst(pool, srv.URL).syncRansomwatch(ctx)

	// .onion が付いていない FQDN には付与される。
	var n int
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM darkweb_ransomware_sites WHERE onion_url = 'itestgroupa-abcdef.onion'`,
	).Scan(&n); err != nil {
		t.Fatalf("件数確認: %v", err)
	}
	if n != 1 {
		t.Errorf(".onion 付与後の登録件数 = %d, want 1", n)
	}

	// 既に .onion 付きなら二重に付けない。
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM darkweb_ransomware_sites WHERE onion_url = 'itestgroupb-ghijkl.onion'`,
	).Scan(&n); err != nil {
		t.Fatalf("件数確認: %v", err)
	}
	if n != 1 {
		t.Errorf(".onion 付きの登録件数 = %d, want 1", n)
	}

	// 空の FQDN は登録しない。
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM darkweb_ransomware_sites WHERE onion_url = '.onion'`).Scan(&n); err != nil {
		t.Fatalf("件数確認: %v", err)
	}
	if n != 0 {
		t.Errorf("空 FQDN が登録されている: %d 件", n)
	}

	// 照合用キャッシュが保存されること。ここが無いと checkPostMatches が
	// 何も見ずに早期リターンする。
	var raw []byte
	if err := pool.QueryRow(ctx,
		`SELECT raw_posts FROM darkweb_ransomware_sites WHERE onion_url = '__cache__'`).Scan(&raw); err != nil {
		t.Fatalf("キャッシュ取得: %v", err)
	}
	if len(raw) == 0 {
		t.Error("キャッシュが空")
	}
}

// TestSyncRansomwatch_ThenCheckPostMatches は同期 → 照合の連結。
// syncRansomwatch がキャッシュを書き、checkPostMatches がそれを読む。
func TestSyncRansomwatch_ThenCheckPostMatches(t *testing.T) {
	pool := darkwebTestPool(t)
	ctx := context.Background()
	const keyword = "itest-chained-corp"
	cleanupSites(t, pool, "ITestChained")

	cleanupKeyword := func() {
		_, _ = pool.Exec(ctx, `DELETE FROM darkweb_findings WHERE monitor_value = $1`, keyword)
		_, _ = pool.Exec(ctx, `DELETE FROM darkweb_monitors WHERE value = $1`, keyword)
	}
	cleanupKeyword()
	t.Cleanup(cleanupKeyword)

	if _, err := pool.Exec(ctx, `
		INSERT INTO darkweb_monitors (monitor_type, value, enabled)
		VALUES ('keyword', $1, TRUE)`, keyword); err != nil {
		t.Fatalf("seed monitors: %v", err)
	}

	body := `[{"name":"ITestChained",
	   "locations":[{"fqdn":"itestchained-xyz.onion","available":true}],
	   "posts":[{"post_title":"ITEST-CHAINED-CORP Inc."}]}]`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	s := newSchedulerAgainst(pool, srv.URL)
	s.syncRansomwatch(ctx)
	s.checkPostMatches(ctx)

	if got := countFindings(t, pool, keyword); got != 1 {
		t.Errorf("同期→照合後の検知件数 = %d, want 1", got)
	}
}

// TestSyncRansomwatch_HTTPErrorIsTolerated は取得失敗で落ちないこと。
func TestSyncRansomwatch_HTTPErrorIsTolerated(t *testing.T) {
	pool := darkwebTestPool(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)

	// 500 応答でも panic せず戻ること。
	newSchedulerAgainst(pool, srv.URL).syncRansomwatch(context.Background())
}

// TestSyncRansomwatch_InvalidJSONIsTolerated はパース失敗で落ちないこと。
// 上流のフォーマット変更で毎回クラッシュするようでは困る。
func TestSyncRansomwatch_InvalidJSONIsTolerated(t *testing.T) {
	pool := darkwebTestPool(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"unexpected": "shape"}`))
	}))
	t.Cleanup(srv.Close)

	newSchedulerAgainst(pool, srv.URL).syncRansomwatch(context.Background())
}

// TestSyncRansomwatch_IsIdempotent は再同期で行が増えないこと。
// onion_url の一意制約と ON CONFLICT に依存している。
func TestSyncRansomwatch_IsIdempotent(t *testing.T) {
	pool := darkwebTestPool(t)
	ctx := context.Background()
	cleanupSites(t, pool, "ITestIdem")

	body := `[{"name":"ITestIdem",
	   "locations":[{"fqdn":"itestidem-aaa.onion","available":true}],"posts":[]}]`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	s := newSchedulerAgainst(pool, srv.URL)
	s.syncRansomwatch(ctx)
	s.syncRansomwatch(ctx)
	s.syncRansomwatch(ctx)

	var n int
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM darkweb_ransomware_sites WHERE onion_url = 'itestidem-aaa.onion'`,
	).Scan(&n); err != nil {
		t.Fatalf("件数確認: %v", err)
	}
	if n != 1 {
		t.Errorf("3 回同期後の件数 = %d, want 1", n)
	}
}
