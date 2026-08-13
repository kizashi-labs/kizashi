//go:build darwin

package darwin

import (
	"strings"
	"testing"
)

// これらは macOS (darwin) タグ付きパッケージの純粋ロジックに対するユニットテストである。
// パッケージ全体が //go:build darwin のため linux の agent-test では実行できず、
// 従来テストが 1 件も無かった。ネットワーク隔離・イベント解析の正しさを担保する。

// ─── buildPFConfig（ネットワーク隔離ルール生成）────────────────────────────
// Windows 側の computeBlockRanges に相当する隔離の要。許可 IP 以外を遮断しつつ、
// ループバック・DNS・EDR サーバ疎通を確実に残すことを検証する。

func TestBuildPFConfig_AlwaysBlocksAndAllowsEssentials(t *testing.T) {
	cfg := buildPFConfig([]string{"10.0.0.5"})

	essentials := []string{
		"pass quick on lo0 all",           // ループバック
		"to any port 53",                  // DNS
		"pass quick from any to 10.0.0.5", // EDR サーバ (下り)
		"pass quick from 10.0.0.5 to any", // EDR サーバ (上り)
		"block all",                       // デフォルト遮断
	}
	for _, want := range essentials {
		if !strings.Contains(cfg, want) {
			t.Errorf("buildPFConfig の出力に %q が含まれるべき\n---\n%s", want, cfg)
		}
	}
}

func TestBuildPFConfig_SkipsEmptyIPs(t *testing.T) {
	cfg := buildPFConfig([]string{"", "192.168.1.10", ""})
	if strings.Contains(cfg, "to \n") || strings.Contains(cfg, "from  to") {
		t.Errorf("空 IP はルール生成をスキップすべき:\n%s", cfg)
	}
	if !strings.Contains(cfg, "192.168.1.10") {
		t.Errorf("空でない IP はルール化されるべき:\n%s", cfg)
	}
}

func TestBuildPFConfig_NoAllowedStillBlocks(t *testing.T) {
	cfg := buildPFConfig(nil)
	if !strings.Contains(cfg, "block all") {
		t.Errorf("許可 IP が無くても block all は必須:\n%s", cfg)
	}
	// 隔離時に完全ロックアウトしないよう、ループバックと DNS は常に許可される。
	if !strings.Contains(cfg, "lo0") || !strings.Contains(cfg, "port 53") {
		t.Errorf("ループバック / DNS は常に許可されるべき:\n%s", cfg)
	}
}

// ─── flagsToAction（fswatch のフラグ → 正規化アクション）───────────────────

func TestFlagsToAction(t *testing.T) {
	cases := []struct {
		flags string
		want  string
	}{
		{"Created IsFile", "create"},
		{"Removed IsFile", "delete"},
		{"Renamed", "rename"},
		{"MovedFrom", "rename"},
		{"MovedTo", "rename"},
		{"Updated IsFile", "modify"},
		{"IsFile OwnerModified", ""}, // 対象外フラグは空文字
		{"", ""},
	}
	for _, tc := range cases {
		if got := flagsToAction(tc.flags); got != tc.want {
			t.Errorf("flagsToAction(%q) = %q, want %q", tc.flags, got, tc.want)
		}
	}
}

// ─── parseLsofAddr（lsof のアドレス表記 → host/port）──────────────────────

func TestParseLsofAddr(t *testing.T) {
	cases := []struct {
		addr     string
		wantHost string
		wantPort uint16
	}{
		{"1.2.3.4:443", "1.2.3.4", 443},
		{"[::1]:8080", "::1", 8080},
		{"[fe80::1]:53", "fe80::1", 53},
		{"nonsense", "nonsense", 0}, // SplitHostPort 失敗時は addr をそのまま返す
	}
	for _, tc := range cases {
		host, port := parseLsofAddr(tc.addr)
		if host != tc.wantHost || port != tc.wantPort {
			t.Errorf("parseLsofAddr(%q) = (%q, %d), want (%q, %d)",
				tc.addr, host, port, tc.wantHost, tc.wantPort)
		}
	}
}

// ─── parseTcpdumpDNS（tcpdump 行 → DNSEvent）──────────────────────────────

func TestParseTcpdumpDNS_AQuery(t *testing.T) {
	line := "12:00:00.000000 IP host.53 > 8.8.8.8.53: 1234+ A? example.com. (30)"
	ev := parseTcpdumpDNS(line)
	if ev == nil {
		t.Fatal("A? クエリ行は DNSEvent を返すべき")
	}
	if ev.Query != "example.com" {
		t.Errorf("Query = %q, want %q (末尾ドット除去)", ev.Query, "example.com")
	}
	if ev.QueryType != "A" {
		t.Errorf("QueryType = %q, want A", ev.QueryType)
	}
}

func TestParseTcpdumpDNS_AAAAQuery(t *testing.T) {
	line := "12:00:00.000000 IP host.53 > 8.8.8.8.53: 1234+ AAAA? ipv6.example.com. (30)"
	ev := parseTcpdumpDNS(line)
	if ev == nil {
		t.Fatal("AAAA? クエリ行は DNSEvent を返すべき")
	}
	if ev.QueryType != "AAAA" {
		t.Errorf("QueryType = %q, want AAAA", ev.QueryType)
	}
}

func TestParseTcpdumpDNS_Ignored(t *testing.T) {
	cases := []string{
		"12:00:00.000000 IP host.443 > 1.2.3.4.443: tcp 100", // DNS ではない
		"short line", // フィールド不足
		"",           // 空行
	}
	for _, line := range cases {
		if ev := parseTcpdumpDNS(line); ev != nil {
			t.Errorf("非 DNS/不正な行は nil を返すべき: %q -> %+v", line, ev)
		}
	}
}

// 既定の監視パスは検知ルールの前提である。Sigma ルールが TargetFilename で
// あるパスを見ていても、収集側がそのディレクトリを見ていなければ**フィールドは
// 解決するのに値が永久に来ない**——このリポジトリが P5-5 / P5-7 で繰り返し
// 潰してきた形になる。実際 migration 386 の
// `macOS Sudoers or Passwd Modification` は、/etc が既定に無かったせいで
// そのままでは発火しなかった。
//
// Linux 側（linux/file_collector.go）には最初から /etc が入っており、
// 非対称だった。ここで両者が揃っていることを固定する。
//
// ★ このテストは Linux の CI では**実行されない**。パッケージ全体が
// `//go:build darwin` で、agent の CI ジョブは ubuntu 上で `go test ./...` を
// 回すため、ここは丸ごとビルド対象外になる。macOS 上で開発する人の手元でだけ
// 走る。CI で効くのは `GOOS=darwin go vet`（型検査）までで、この表明そのものは
// 検証されない——「緑だから守られている」と読まないこと。
func TestDarwinDefaultWatchDirsCoverRuleTargets(t *testing.T) {
	c := NewDarwinFileCollector(nil)

	// 出荷ルールが TargetFilename で見ている場所。増やすときは、対応する
	// ルールがあることを確かめてから足すこと（監視範囲はノイズ量に直結する）。
	required := map[string]string{
		"/etc":                   "sudoers / passwd 改変 (T1548.003)",
		"/Library/LaunchAgents":  "LaunchAgent plist 作成 (T1543.001)",
		"/Library/LaunchDaemons": "LaunchDaemon plist 作成 (T1543.004)",
		"/Users":                 "シェル起動ファイル改変 (T1546.004)",
	}

	have := make(map[string]bool, len(c.monitored))
	for _, d := range c.monitored {
		have[d] = true
	}
	for dir, why := range required {
		if !have[dir] {
			t.Errorf("既定の監視パスに %s が無い（%s のルールが発火しなくなる）。"+
				"現在の監視パス: %v", dir, why, c.monitored)
		}
	}
}
