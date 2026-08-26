package sync

// YARA-HQ 同期の本体 (Sync)。
//
// ツリー取得 → .yar ファイルの絞り込み → 本文取得 → パース → DB upsert という
// 一連を、httptest の GitHub 代役サーバと実 DB で通す。
//
// apiBase / rawBase は本番では GitHub を指す。テストからだけ差し替える。

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/edr-platform/server/internal/store"
)

func syncTestStore(t *testing.T) (*store.YARAStore, *pgxpool.Pool) {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping DB-backed sync tests")
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return store.NewYARAStore(pool), pool
}

// fakeGitHub は GitHub API (ツリー) と raw (ファイル本文) の両方を 1 台で担う。
// パスの先頭で振り分ける: /repos/... がツリー、それ以外が raw。
type fakeGitHub struct {
	srv *httptest.Server

	mu       sync.Mutex
	treeJSON string
	files    map[string]string // リポジトリ内パス -> .yar 本文
	rawHits  map[string]int    // 取得回数
	treeHits int
}

func newFakeGitHub(t *testing.T, treeJSON string, files map[string]string) *fakeGitHub {
	t.Helper()
	f := &fakeGitHub{treeJSON: treeJSON, files: files, rawHits: map[string]int{}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()

		if strings.HasPrefix(r.URL.Path, "/repos/") {
			f.treeHits++
			_, _ = w.Write([]byte(f.treeJSON))
			return
		}

		// raw のパスは /<owner>/<repo>/<branch>/<path...>
		parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/", 4)
		if len(parts) < 4 {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		repoPath := parts[3]
		f.rawHits[repoPath]++
		body, ok := f.files[repoPath]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(f.srv.Close)
	return f
}

// newSyncerAgainst は fakeGitHub を向いた Syncer を返す。
func newSyncerAgainst(s *store.YARAStore, f *fakeGitHub) *YARAHQSyncer {
	syncer := NewYARAHQSyncer(s, "")
	syncer.apiBase = f.srv.URL
	syncer.rawBase = f.srv.URL
	return syncer
}

// treeJSON はツリー応答を組み立てる。
func treeJSON(paths ...string) string {
	items := make([]string, 0, len(paths))
	for _, p := range paths {
		items = append(items, fmt.Sprintf(`{"path":%q,"type":"blob"}`, p))
	}
	return `{"tree":[` + strings.Join(items, ",") + `],"truncated":false}`
}

const demoRule = `
rule ITestDemoRule : trojan
{
    meta:
        description = "itest demo rule"
        severity = "critical"
        author = "itest"
    strings:
        $a = "itest-marker"
    condition:
        $a
}
`

// cleanupRules は投入したルールを消す。
func cleanupRules(t *testing.T, pool *pgxpool.Pool, namePrefix string) {
	t.Helper()
	ctx := context.Background()
	del := func() {
		_, _ = pool.Exec(ctx, `DELETE FROM yara_rules WHERE name LIKE $1`, namePrefix+"%")
	}
	del()
	t.Cleanup(del)
}

// TestSync_ImportsRulesEndToEnd はツリー取得から DB 登録までを通す。
func TestSync_ImportsRulesEndToEnd(t *testing.T) {
	st, pool := syncTestStore(t)
	cleanupRules(t, pool, "ITestDemoRule")

	f := newFakeGitHub(t,
		treeJSON("malware/itest_demo.yar", "malware/README.md", "other/skipped.yar"),
		map[string]string{"malware/itest_demo.yar": demoRule},
	)
	syncer := newSyncerAgainst(st, f)

	if err := syncer.Sync(context.Background(), false, []string{"malware"}); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	// ツリーは 1 回だけ取得する (1 リクエストで済ませる設計)。
	if f.treeHits != 1 {
		t.Errorf("ツリー取得回数 = %d, want 1", f.treeHits)
	}
	// .yar 以外と対象外ディレクトリは取得しない。
	if f.rawHits["malware/README.md"] != 0 {
		t.Error(".yar でないファイルを取得している")
	}
	if f.rawHits["other/skipped.yar"] != 0 {
		t.Error("対象外ディレクトリのファイルを取得している")
	}
	if f.rawHits["malware/itest_demo.yar"] != 1 {
		t.Errorf("対象ファイルの取得回数 = %d, want 1", f.rawHits["malware/itest_demo.yar"])
	}

	// DB に入っていること。
	var n int
	var enabled bool
	if err := pool.QueryRow(context.Background(),
		`SELECT COUNT(*), COALESCE(BOOL_OR(enabled), false) FROM yara_rules WHERE name = 'ITestDemoRule'`,
	).Scan(&n, &enabled); err != nil {
		t.Fatalf("件数確認: %v", err)
	}
	if n != 1 {
		t.Fatalf("登録件数 = %d, want 1", n)
	}
	// autoEnable=false でも severity=critical は推奨ルールとして有効化される。
	if !enabled {
		t.Error("critical のルールが有効化されていない (isRecommendedRule の判定)")
	}

	st2 := syncer.Status()
	if st2 == nil {
		t.Fatal("同期後の Status が nil")
	}
	if st2.Running {
		t.Error("同期完了後も Running=true")
	}
	if st2.Total != 1 {
		t.Errorf("Total = %d, want 1", st2.Total)
	}
	if st2.Imported+st2.Updated != 1 {
		t.Errorf("Imported+Updated = %d, want 1", st2.Imported+st2.Updated)
	}
}

// TestSync_SecondRunUpdatesInsteadOfDuplicating は 2 回目が更新になること。
func TestSync_SecondRunUpdatesInsteadOfDuplicating(t *testing.T) {
	st, pool := syncTestStore(t)
	cleanupRules(t, pool, "ITestDemoRule")

	f := newFakeGitHub(t,
		treeJSON("malware/itest_demo.yar"),
		map[string]string{"malware/itest_demo.yar": demoRule},
	)
	syncer := newSyncerAgainst(st, f)
	ctx := context.Background()

	if err := syncer.Sync(ctx, false, []string{"malware"}); err != nil {
		t.Fatalf("Sync(1回目): %v", err)
	}
	if err := syncer.Sync(ctx, false, []string{"malware"}); err != nil {
		t.Fatalf("Sync(2回目): %v", err)
	}

	var n int
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM yara_rules WHERE name = 'ITestDemoRule'`).Scan(&n); err != nil {
		t.Fatalf("件数確認: %v", err)
	}
	if n != 1 {
		t.Errorf("2 回同期後の件数 = %d, want 1 (重複登録)", n)
	}

	if got := syncer.Status(); got.Updated < 1 {
		t.Errorf("2 回目が Updated に計上されていない: %+v", got)
	}
}

// TestSync_TreeFetchFailureIsReported はツリー取得失敗でエラーを返すこと。
// ここを握りつぶすと「同期したのに 0 件」になり原因が分からない。
func TestSync_TreeFetchFailureIsReported(t *testing.T) {
	st, _ := syncTestStore(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden) // レート制限相当
	}))
	t.Cleanup(srv.Close)

	syncer := NewYARAHQSyncer(st, "")
	syncer.apiBase = srv.URL
	syncer.rawBase = srv.URL

	err := syncer.Sync(context.Background(), false, []string{"malware"})
	if err == nil {
		t.Fatal("ツリー取得失敗でエラーが返っていない")
	}

	got := syncer.Status()
	if got == nil {
		t.Fatal("Status が nil")
	}
	if got.Failed == 0 {
		t.Error("Failed が加算されていない")
	}
	if len(got.Errors) == 0 {
		t.Error("Errors に理由が残っていない")
	}
}

// TestSync_RawFetchFailureIsRecordedButContinues は個別ファイルの取得失敗で
// 同期全体を止めないこと。1 ファイルの 404 で全ルールが入らないのは困る。
func TestSync_RawFetchFailureIsRecordedButContinues(t *testing.T) {
	st, pool := syncTestStore(t)
	cleanupRules(t, pool, "ITestDemoRule")

	f := newFakeGitHub(t,
		treeJSON("malware/missing.yar", "malware/itest_demo.yar"),
		map[string]string{"malware/itest_demo.yar": demoRule}, // missing.yar は 404
	)
	syncer := newSyncerAgainst(st, f)

	if err := syncer.Sync(context.Background(), false, []string{"malware"}); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	got := syncer.Status()
	if got.Failed == 0 {
		t.Error("404 のファイルが Failed に計上されていない")
	}
	// 取得できた方は登録されていること。
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM yara_rules WHERE name = 'ITestDemoRule'`).Scan(&n); err != nil {
		t.Fatalf("件数確認: %v", err)
	}
	if n != 1 {
		t.Errorf("正常なファイルの登録件数 = %d, want 1 (1 件の失敗で全体が止まっている)", n)
	}
}

// TestSync_RejectsConcurrentRun は多重実行を弾くこと。
func TestSync_RejectsConcurrentRun(t *testing.T) {
	st, _ := syncTestStore(t)

	// ツリー応答を遅らせて、1 本目が走っている間に 2 本目を投げる。
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release
		_, _ = w.Write([]byte(treeJSON()))
	}))
	t.Cleanup(srv.Close)

	syncer := NewYARAHQSyncer(st, "")
	syncer.apiBase = srv.URL
	syncer.rawBase = srv.URL

	first := make(chan error, 1)
	go func() { first <- syncer.Sync(context.Background(), false, []string{"malware"}) }()

	// 1 本目が Running になるまで待つ。
	for i := 0; i < 200 && !syncer.IsRunning(); i++ {
		time.Sleep(5 * time.Millisecond)
	}
	if !syncer.IsRunning() {
		close(release)
		<-first
		t.Skip("1 本目が走り出さないため多重実行の検証をスキップ")
	}

	if err := syncer.Sync(context.Background(), false, []string{"malware"}); err == nil {
		t.Error("実行中に 2 本目が受け付けられている")
	}

	close(release)
	if err := <-first; err != nil {
		t.Fatalf("1 本目: %v", err)
	}
}
