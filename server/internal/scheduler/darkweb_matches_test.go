package scheduler

// ダークウェブ監視の照合処理。
//
// syncRansomwatch / healthCheck は取得先 URL がハードコード (ransomwatchURL) か
// Tor プロキシ経由のためテストから差し替えられない。一方 checkPostMatches は
// DB に入ったキャッシュと監視キーワードを突き合わせるだけなので、外部に出ずに
// 全経路を実行できる。ここが壊れると「被害者リストに自社名が載っても検知
// されない」という、最も気づきにくい形の失敗になる。

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func darkwebTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping DB-backed darkweb tests")
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// seedDarkwebCache は監視キーワードと、被害者リストのキャッシュを用意する。
// postTitles は 1 グループ分の投稿タイトル。
func seedDarkwebCache(t *testing.T, pool *pgxpool.Pool, keyword, groupName string, postTitles []string) {
	t.Helper()
	ctx := context.Background()

	cleanup := func() {
		_, _ = pool.Exec(ctx, `DELETE FROM darkweb_findings WHERE monitor_value = $1`, keyword)
		_, _ = pool.Exec(ctx, `DELETE FROM darkweb_monitors WHERE value = $1`, keyword)
		_, _ = pool.Exec(ctx, `DELETE FROM darkweb_ransomware_sites WHERE onion_url = '__cache__'`)
	}
	cleanup()
	t.Cleanup(cleanup)

	if _, err := pool.Exec(ctx, `
		INSERT INTO darkweb_monitors (monitor_type, value, enabled)
		VALUES ('keyword', $1, TRUE)`, keyword); err != nil {
		t.Fatalf("seed darkweb_monitors: %v", err)
	}

	type post struct {
		PostTitle string `json:"post_title"`
	}
	type group struct {
		Name  string `json:"name"`
		Posts []post `json:"posts"`
	}
	posts := make([]post, 0, len(postTitles))
	for _, p := range postTitles {
		posts = append(posts, post{PostTitle: p})
	}
	raw, err := json.Marshal([]group{{Name: groupName, Posts: posts}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	if _, err := pool.Exec(ctx, `
		INSERT INTO darkweb_ransomware_sites (group_name, onion_url, source, raw_posts)
		VALUES ('cache', '__cache__', 'test', $1)
		ON CONFLICT (onion_url) DO UPDATE SET raw_posts = EXCLUDED.raw_posts`, raw); err != nil {
		t.Fatalf("seed cache: %v", err)
	}
}

func countFindings(t *testing.T, pool *pgxpool.Pool, keyword string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM darkweb_findings WHERE monitor_value = $1`, keyword).Scan(&n); err != nil {
		t.Fatalf("件数確認: %v", err)
	}
	return n
}

// TestCheckPostMatches_DetectsKeywordInVictimList はキーワード一致で検知が
// 登録されること。
func TestCheckPostMatches_DetectsKeywordInVictimList(t *testing.T) {
	pool := darkwebTestPool(t)
	const keyword = "itest-victim-corp"

	seedDarkwebCache(t, pool, keyword, "LockBit", []string{
		"ITEST-VICTIM-CORP Ltd.", // 大文字でも一致すること
		"unrelated company",
	})

	s := NewDarkWebScheduler(pool, "", false)
	s.checkPostMatches(context.Background())

	if got := countFindings(t, pool, keyword); got != 1 {
		t.Fatalf("検知件数 = %d, want 1", got)
	}

	// 深刻度と本文にグループ名が入ること。運用者がこれだけで判断できる必要がある。
	var severity int
	var title, desc string
	if err := pool.QueryRow(context.Background(), `
		SELECT severity, title, description FROM darkweb_findings
		WHERE monitor_value = $1`, keyword).Scan(&severity, &title, &desc); err != nil {
		t.Fatalf("検知内容の取得: %v", err)
	}
	if severity != 9 {
		t.Errorf("severity = %d, want 9", severity)
	}
	for _, want := range []string{"LockBit"} {
		if !strings.Contains(title, want) && !strings.Contains(desc, want) {
			t.Errorf("グループ名 %q が題名にも本文にも無い (title=%q)", want, title)
		}
	}
}

// TestCheckPostMatches_IsIdempotent は同じ投稿で二重に検知を作らないこと。
// スケジューラは繰り返し走るので、ここが効かないと同じ被害が毎回アラートになる。
func TestCheckPostMatches_IsIdempotent(t *testing.T) {
	pool := darkwebTestPool(t)
	const keyword = "itest-dedup-corp"

	seedDarkwebCache(t, pool, keyword, "BlackCat", []string{"itest-dedup-corp"})

	s := NewDarkWebScheduler(pool, "", false)
	ctx := context.Background()
	s.checkPostMatches(ctx)
	s.checkPostMatches(ctx)
	s.checkPostMatches(ctx)

	if got := countFindings(t, pool, keyword); got != 1 {
		t.Errorf("3 回実行後の検知件数 = %d, want 1 (重複チェックが効いていない)", got)
	}
}

// TestCheckPostMatches_NoMatchCreatesNothing は無関係な投稿で検知しないこと。
func TestCheckPostMatches_NoMatchCreatesNothing(t *testing.T) {
	pool := darkwebTestPool(t)
	const keyword = "itest-absent-corp"

	seedDarkwebCache(t, pool, keyword, "Cl0p", []string{
		"some other company", "yet another victim",
	})

	NewDarkWebScheduler(pool, "", false).checkPostMatches(context.Background())

	if got := countFindings(t, pool, keyword); got != 0 {
		t.Errorf("検知件数 = %d, want 0 (誤検知)", got)
	}
}

// TestCheckPostMatches_NoCacheReturnsEarly はキャッシュ未取得時に何もしないこと。
func TestCheckPostMatches_NoCacheReturnsEarly(t *testing.T) {
	pool := darkwebTestPool(t)
	ctx := context.Background()
	const keyword = "itest-nocache-corp"

	cleanup := func() {
		_, _ = pool.Exec(ctx, `DELETE FROM darkweb_findings WHERE monitor_value = $1`, keyword)
		_, _ = pool.Exec(ctx, `DELETE FROM darkweb_monitors WHERE value = $1`, keyword)
		_, _ = pool.Exec(ctx, `DELETE FROM darkweb_ransomware_sites WHERE onion_url = '__cache__'`)
	}
	cleanup()
	t.Cleanup(cleanup)

	if _, err := pool.Exec(ctx, `
		INSERT INTO darkweb_monitors (monitor_type, value, enabled)
		VALUES ('keyword', $1, TRUE)`, keyword); err != nil {
		t.Fatalf("seed monitors: %v", err)
	}

	// キャッシュ行を作らないまま実行。落ちずに何も登録しないこと。
	NewDarkWebScheduler(pool, "", false).checkPostMatches(ctx)

	if got := countFindings(t, pool, keyword); got != 0 {
		t.Errorf("検知件数 = %d, want 0", got)
	}
}

// TestDarkWebScheduler_DisabledRunReturns は enabled=false で Run が即戻ること。
func TestDarkWebScheduler_DisabledRunReturns(t *testing.T) {
	pool := darkwebTestPool(t)

	done := make(chan struct{})
	go func() {
		NewDarkWebScheduler(pool, "", false).Run(context.Background())
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("enabled=false でも Run が戻らない")
	}
}
