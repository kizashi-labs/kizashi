package scheduler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// ダークウェブ監視が**オプトイン**であることを固定する。
//
// 背景: 判定は長く `os.Getenv("DARKWEB_MONITOR_ENABLED") != "false"` で、
// 既定 ON だった。`docker compose up` しただけの環境が、起動直後に
// ransomwatch / ransomware.live へ出ていく。README の「既定では何も
// 外に出ない」と食い違っており、既定を OFF に倒した。
// 未設定＝無効がここで崩れると同じ状態に戻るので、テストで固定する。
func TestDarkWebEnabledIsOptIn(t *testing.T) {
	cases := []struct {
		env  string
		want bool
	}{
		{"", false},      // 未設定 → 無効（これが本丸）
		{"false", false}, // 明示的な無効
		{"0", false},     // true 以外は無効
		{"yes", false},   // 「それらしい」値でも有効にはしない
		{"TRUE", true},   // 大文字小文字は問わない
		{" true ", true}, // .env の余分な空白を許容
		{"true", true},   // 明示的な有効化
	}
	for _, c := range cases {
		if got := DarkWebEnabled(c.env); got != c.want {
			t.Errorf("DarkWebEnabled(%q) = %v, want %v", c.env, got, c.want)
		}
	}
}

// enabled=false のスケジューラーがネットワークに一切触れないことを確認する。
// 「無効なのに起動直後の 1 回だけは走る」という壊れ方を防ぐ。
func TestDarkWebSchedulerDisabledMakesNoRequests(t *testing.T) {
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.Write([]byte("[]"))
	}))
	defer srv.Close()

	// pool は nil。無効なら DB にも触れないので、触れれば panic して落ちる。
	s := NewDarkWebScheduler(nil, "", false)
	s.ransomwatchURL = srv.URL

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		s.Run(ctx)
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("Run が即座に戻りませんでした。enabled=false は何もせず返るべきです")
	}

	if n := atomic.LoadInt64(&hits); n != 0 {
		t.Errorf("無効なのに %d 件の外向きリクエストが発生しました", n)
	}
}

// ベース compose が「起動しただけで外に出ない」ままであることを確認する。
//
// コードの既定を OFF にしても、compose 側が `DARKWEB_MONITOR_ENABLED: true` を
// 渡していれば意味がない。Tor コンテナがベースに居るのも同じで、
// 「既定構成に含まれている＝使うのが前提」と読めてしまう。両方を固定する。
func TestBaseComposeDoesNotEnableDarkWeb(t *testing.T) {
	root := repoRootFromSchedulerPkg(t)
	base := mustReadFile(t, filepath.Join(root, "docker-compose.yml"))

	// 1) tor サービスはベースに居ない（オーバーレイ側にだけ居る）
	for _, line := range strings.Split(base, "\n") {
		if strings.TrimRight(line, " \t") == "  tor:" {
			t.Error("docker-compose.yml に tor サービスが復活しています。" +
				"ダークウェブ監視は docker-compose.darkweb.yml に分離してください")
		}
	}

	// 2) 既定値は false
	if !strings.Contains(base, "DARKWEB_MONITOR_ENABLED: ${DARKWEB_MONITOR_ENABLED:-false}") {
		t.Error("docker-compose.yml の DARKWEB_MONITOR_ENABLED の既定が false ではありません")
	}

	// 3) オーバーレイは存在し、tor と有効化をまとめて持っている
	overlay := mustReadFile(t, filepath.Join(root, "docker-compose.darkweb.yml"))
	for _, want := range []string{"tor:", `DARKWEB_MONITOR_ENABLED: "true"`} {
		if !strings.Contains(overlay, want) {
			t.Errorf("docker-compose.darkweb.yml に %q がありません", want)
		}
	}
}

func mustReadFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("読み込みに失敗: %s: %v", path, err)
	}
	return string(b)
}

// repoRootFromSchedulerPkg は internal/scheduler から見たリポジトリルートを返す。
func repoRootFromSchedulerPkg(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("作業ディレクトリの取得に失敗: %v", err)
	}
	// .../server/internal/scheduler → .../
	root := filepath.Clean(filepath.Join(wd, "..", "..", ".."))
	if _, err := os.Stat(filepath.Join(root, "docker-compose.yml")); err != nil {
		t.Skipf("compose ファイルが同梱されていないためスキップします: %v", err)
	}
	return root
}

// 外向き通信のスイッチが、既定値ごと README の表と一致していること。
//
// ダークウェブ監視はオプトイン（未設定＝無効）、公開ブロックリストと NVD 照会は
// オプトアウト（未設定＝有効）。この非対称は意図的で、後者は IOC 照合と脆弱性
// 検出の母数に直結するため。既定を取り違えると、片方は「黙って外に出る」、
// もう片方は「入れたのに検知しない」に化ける。
func TestOutboundSwitchDefaults(t *testing.T) {
	cases := []struct {
		name string
		fn   func(string) bool
		env  string
		want bool
	}{
		{"feeds/未設定は有効", ThreatFeedSyncEnabled, "", true},
		{"feeds/false で無効", ThreatFeedSyncEnabled, "false", false},
		{"feeds/FALSE も無効", ThreatFeedSyncEnabled, "FALSE", false},
		{"feeds/空白込みでも無効", ThreatFeedSyncEnabled, " false ", false},
		{"feeds/true は有効", ThreatFeedSyncEnabled, "true", true},
		{"feeds/未知の値は既定の有効", ThreatFeedSyncEnabled, "0", true},

		{"nvd/未設定は有効", NVDLookupEnabled, "", true},
		{"nvd/false で無効", NVDLookupEnabled, "false", false},
		{"nvd/未知の値は既定の有効", NVDLookupEnabled, "no", true},
	}
	for _, c := range cases {
		if got := c.fn(c.env); got != c.want {
			t.Errorf("%s: %q → %v, want %v", c.name, c.env, got, c.want)
		}
	}
}

// enabled=false のフィードスケジューラーがネットワークにも DB にも触れないこと。
// pool は nil なので、DB に触れれば panic して落ちる。
func TestFeedSchedulerDisabledDoesNothing(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		NewFeedScheduler(nil, nil, time.Hour).WithEnabled(false).Run(ctx)
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("Run が即座に戻りませんでした。enabled=false は何もせず返るべきです")
	}
}

// インポーター側も同じスイッチで止まること。両方止めないと、同じ
// threat_feeds を引く経路が片方だけ残って外向き通信が消えない。
func TestThreatFeedImporterDisabledDoesNothing(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		NewThreatFeedImporter(nil, nil).WithEnabled(false).Run(ctx)
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("Run が即座に戻りませんでした。enabled=false は何もせず返るべきです")
	}
}

// NVD_LOOKUP_ENABLED=false のとき lookupNVD がネットワークに触れないこと。
func TestNVDLookupDisabledMakesNoRequest(t *testing.T) {
	t.Setenv("NVD_LOOKUP_ENABLED", "false")
	if entry := lookupNVD(context.Background(), "openssl"); entry != nil {
		t.Errorf("無効なのに結果が返りました: %+v", entry)
	}
}
