//go:build linux

package linux

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/edr-platform/agent/internal/collector"
)

// 実機検証(2026-08-01)で判明した死角の回帰テスト。
//
// inotify は「そのディレクトリ1つ」しか監視しない。設定されたルートだけに watch を
// 張っていたため、サブディレクトリ配下の操作が完全に不可視だった。実機では /tmp 直下の
// 作成/追記/リネームは正しく届く一方、/tmp/<サブディレクトリ>/ 内で70ファイルを
// modify+rename しても**ファイルイベントが1件も出なかった**。ランサムウェアが実際に
// 暗号化するのは /home/<user>/Documents/ のような深い階層なので、この死角は
// T1486 検知を原理的に不可能にしていた。
func TestInotify_WatchesSubdirectories(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "deep", "deeper")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}

	c := NewInotifyFileCollector()
	c.SetPaths([]string{root}, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := make(chan collector.FileEvent, 256)
	if err := c.Start(ctx, out); err != nil {
		t.Skipf("inotify を初期化できない環境: %v", err)
	}
	defer c.Stop()

	target := filepath.Join(sub, "victim.doc")
	if err := os.WriteFile(target, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	// 既存ファイルへの破壊的操作(ランサムの本体)
	if err := os.WriteFile(target, []byte("encrypted"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(target, target+".locked"); err != nil {
		t.Fatal(err)
	}

	if !waitForPath(t, out, sub, 3*time.Second) {
		t.Fatal("サブディレクトリ配下のファイル操作が1件も届いていない(ランサム検知の死角)")
	}
}

// 起動後に作られたディレクトリも監視対象に入ること。攻撃者は着地後に作業用
// ディレクトリを作るので、起動時スナップショットだけでは取り逃がす。
func TestInotify_WatchesDirectoriesCreatedAfterStart(t *testing.T) {
	root := t.TempDir()

	c := NewInotifyFileCollector()
	c.SetPaths([]string{root}, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := make(chan collector.FileEvent, 256)
	if err := c.Start(ctx, out); err != nil {
		t.Skipf("inotify を初期化できない環境: %v", err)
	}
	defer c.Stop()

	staging := filepath.Join(root, "staging")
	if err := os.Mkdir(staging, 0o755); err != nil {
		t.Fatal(err)
	}
	// watch 追加が readEvents で処理されるまで待つ
	time.Sleep(300 * time.Millisecond)

	f := filepath.Join(staging, "payload.bin")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f, []byte("y"), 0o644); err != nil {
		t.Fatal(err)
	}

	if !waitForPath(t, out, staging, 3*time.Second) {
		t.Fatal("起動後に作成されたディレクトリ配下の操作が届いていない")
	}
}

// 除外パス配下には watch を張らないこと。
func TestInotify_HonoursExclusions(t *testing.T) {
	root := t.TempDir()
	skip := filepath.Join(root, "skipme")
	if err := os.MkdirAll(skip, 0o755); err != nil {
		t.Fatal(err)
	}

	c := NewInotifyFileCollector()
	c.SetPaths([]string{root}, []string{skip})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := make(chan collector.FileEvent, 64)
	if err := c.Start(ctx, out); err != nil {
		t.Skipf("inotify を初期化できない環境: %v", err)
	}
	defer c.Stop()

	for _, p := range c.watchDirs {
		if p == skip {
			t.Fatalf("除外パスに watch が張られている: %s", p)
		}
	}
}

// waitForPath reports whether any event under dir arrives before the deadline.
func waitForPath(t *testing.T, out <-chan collector.FileEvent, dir string, wait time.Duration) bool {
	t.Helper()
	deadline := time.After(wait)
	for {
		select {
		case evt := <-out:
			if filepath.Dir(evt.Path) == dir {
				return true
			}
		case <-deadline:
			return false
		}
	}
}

// 実機(2026-08-01)では Go モジュールキャッシュだけで watch 枠を使い切り、
// /root・/usr/bin・実行時に作られた /tmp 配下のディレクトリに1つも watch を
// 張れなかった。ビルド/パッケージキャッシュは書き込み一回限りの成果物置き場で、
// 攻撃者がユーザー文書を暗号化する経路とは無関係なので、走査から除外する。
func TestInotify_SkipsBuildCaches(t *testing.T) {
	root := t.TempDir()
	cache := filepath.Join(root, "go", "pkg", "mod", "cache", "download", "x")
	docs := filepath.Join(root, "Documents")
	for _, d := range []string{cache, docs} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	c := NewInotifyFileCollector()
	c.SetPaths([]string{root}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := make(chan collector.FileEvent, 64)
	if err := c.Start(ctx, out); err != nil {
		t.Skipf("inotify を初期化できない環境: %v", err)
	}
	defer c.Stop()

	var sawCache, sawDocs bool
	for _, p := range c.watchDirs {
		if strings.Contains(p, "/go/pkg/mod") {
			sawCache = true
		}
		if p == docs {
			sawDocs = true
		}
	}
	if sawCache {
		t.Error("ビルドキャッシュに watch を張っている(枠を食い潰す)")
	}
	if !sawDocs {
		t.Error("ユーザー文書ディレクトリに watch が張られていない")
	}
}

// watch 上限はカーネルの max_user_watches から導出する。固定値だと
// 上限より遥かに低い場合に無駄な死角を作り、高い場合は ENOSPC で全滅する。
func TestInotifyWatchBudget_DerivedFromKernelLimit(t *testing.T) {
	b := inotifyWatchBudget()
	if b < 1024 {
		t.Fatalf("予算が小さすぎる: %d", b)
	}
	raw, err := os.ReadFile("/proc/sys/fs/inotify/max_user_watches")
	if err != nil {
		t.Skip("max_user_watches を読めない環境")
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Skip("max_user_watches を解釈できない")
	}
	if b > n {
		t.Fatalf("カーネル上限(%d)を超える予算(%d)は ENOSPC を招く", n, b)
	}
}

// 実機(2026-08-01)では `go build` が30秒で120ファイルを書き、ランサムウェアの
// レート検知器を誤発火させた。「通常の一括操作は閾値に届かない」という設計前提が
// ビルドには当てはまらない。コンパイラのスクラッチ領域は一時的かつツール専有なので、
// センサー段で落として誤検知の源を断つ。
func TestRuntimeNoise_FiltersCompilerScratch(t *testing.T) {
	noisy := []string{
		"/tmp/go-build3953913584/b001/_pkg_.a",
		"/tmp/ccache/a/b.o",
		"/tmp/runc-process123",
	}
	for _, p := range noisy {
		if !isRuntimeNoisePath(p) {
			t.Errorf("ビルド/ランタイムのスクラッチが濾過されていない: %s", p)
		}
	}
	// ユーザーデータは絶対に落とさない
	real := []string{
		"/home/user/Documents/report.docx",
		"/tmp/important.txt",
		"/tmp/go-notes.md",
	}
	for _, p := range real {
		if isRuntimeNoisePath(p) {
			t.Errorf("ユーザーデータを濾過してしまっている: %s", p)
		}
	}
}
