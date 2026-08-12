package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeCSV(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("fixture 書き込み失敗: %v", err)
	}
	return p
}

func TestExtractDate(t *testing.T) {
	cases := map[string]string{
		"live-20260629-windows.csv": "2026-06-29",
		"scorecard.csv":             "",
		"live-20260702-x.csv":       "2026-07-02",
	}
	for in, want := range cases {
		if got := extractDate(in); got != want {
			t.Errorf("extractDate(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestExtractPlatform(t *testing.T) {
	cases := map[string]string{
		"live-20260629-windows-superspy-fullchain.csv":  "windows",
		"live-20260630-linux-thief-fullchain.csv":       "linux",
		"live-20260702-windows-discovery-scorecard.csv": "windows",
		"live-20260726-windows-scorecard.csv":           "windows",
		"live-20260801-macos-esf.csv":                   "darwin", // macos は darwin に正規化
		"live-20260801-darwin-x.csv":                    "darwin",
		"live-20260801-scorecard.csv":                   "", // 判別不能
		"scorecard.csv":                                 "",
	}
	for in, want := range cases {
		if got := extractPlatform(in); got != want {
			t.Errorf("extractPlatform(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSummarise_BestRankPerTechnique(t *testing.T) {
	// T1005 は Tactic(3) 止まり、T1074.001 は複数行のうち Technique(4) を採用、
	// T1566.001 は None(0)=見逃し。latency は検知行の最小を代表値に。
	csv := "technique,test_name,rank,rank_name,latency_sec,matched_by,exit_code\n" +
		"T1005,find,3,Tactic,9.0,ruleA,0\n" +
		"T1074.001,stage,3,Tactic,5.0,ruleB,0\n" +
		"T1074.001,stage,4,Technique,1.0,ruleB,0\n" +
		"T1566.001,phish,0,None,,,0\n"
	p := writeCSV(t, "live-20260630-test.csv", csv)

	s, err := summarise(p)
	if err != nil {
		t.Fatalf("summarise: %v", err)
	}
	if s.Techniques != 3 {
		t.Errorf("Techniques = %d, want 3", s.Techniques)
	}
	if s.Date != "2026-06-30" {
		t.Errorf("Date = %q, want 2026-06-30", s.Date)
	}
	// 可視性: rank>=1 は T1005,T1074.001 の2件（T1566.001 は None）→ 66.7%
	if s.VisibilityPct != 66.7 {
		t.Errorf("VisibilityPct = %.1f, want 66.7", s.VisibilityPct)
	}
	// 検知(Tactic+): 2/3 = 66.7%
	if s.DetectionPct != 66.7 {
		t.Errorf("DetectionPct = %.1f, want 66.7", s.DetectionPct)
	}
	// 解析検知(Technique): 1/3 = 33.3%（T1074.001 のみ最良が4）
	if s.TechniquePct != 33.3 {
		t.Errorf("TechniquePct = %.1f, want 33.3", s.TechniquePct)
	}
	if s.Misses != 1 {
		t.Errorf("Misses = %d, want 1", s.Misses)
	}
	// MTTD 中央値: 検知した technique の代表 latency = {T1005:9.0, T1074.001:1.0} → 中央値 5.0
	if s.MTTDMedianSec != 5.0 {
		t.Errorf("MTTDMedianSec = %.1f, want 5.0", s.MTTDMedianSec)
	}
}

func TestSummarise_AllDetected(t *testing.T) {
	csv := "technique,test_name,rank,rank_name,latency_sec,matched_by,exit_code\n" +
		"T1059.001,a,4,Technique,3.0,r,0\n" +
		"T1003.001,b,4,Technique,4.0,r,0\n"
	p := writeCSV(t, "live-20260629-x.csv", csv)
	s, err := summarise(p)
	if err != nil {
		t.Fatalf("summarise: %v", err)
	}
	if s.DetectionPct != 100 || s.TechniquePct != 100 || s.Misses != 0 {
		t.Errorf("全 Technique 検知を期待: got detection=%.1f technique=%.1f misses=%d",
			s.DetectionPct, s.TechniquePct, s.Misses)
	}
	if s.MTTDMedianSec != 3.5 { // {3.0,4.0} の中央値
		t.Errorf("MTTDMedianSec = %.1f, want 3.5", s.MTTDMedianSec)
	}
}

func TestSummarise_MissingColumns(t *testing.T) {
	p := writeCSV(t, "bad.csv", "foo,bar\n1,2\n")
	if _, err := summarise(p); err == nil {
		t.Error("technique/rank 列が無いCSVはエラーを返すべき")
	}
}

// BOM 付き CSV でも列を解決できること。剥がせないと「technique 列が無い」と
// 誤判定してファイルごと集計から静かに落ち、回帰ゲートが素通りする。
func TestSummarise_UTF8BOMHeader(t *testing.T) {
	csv := "\ufefftechnique,test_name,rank,rank_name,latency_sec,matched_by,exit_code\n" +
		"T1033,a,4,Technique,1.0,r,0\n"
	s, err := summarise(writeCSV(t, "live-20260726-bom.csv", csv))
	if err != nil {
		t.Fatalf("BOM 付きCSVを読めるべき: %v", err)
	}
	if s.Techniques != 1 || s.DetectionPct != 100 {
		t.Errorf("techniques=%d detection=%.1f, want 1 / 100", s.Techniques, s.DetectionPct)
	}
}

// mustSummarise は CSV 文字列から Summary を作るテストヘルパ。
func mustSummarise(t *testing.T, name, csv string) *Summary {
	t.Helper()
	s, err := summarise(writeCSV(t, name, csv))
	if err != nil {
		t.Fatalf("summarise(%s): %v", name, err)
	}
	return s
}

const header = "technique,test_name,rank,rank_name,latency_sec,matched_by,exit_code\n"

// 母集団が広がっただけ(既存技法は全部検知したまま、新しく難しい技法を計測対象に
// 加えた)ケースを回帰と誤判定しないこと。これが実際に CI を落とした事象
// (live-20260702-windows-discovery 13技100% → live-20260726-windows 12技66.7%)。
func TestCheckRegression_MoreTechniquesIsNotRegression(t *testing.T) {
	prev := mustSummarise(t, "live-20260702-a.csv", header+
		"T1033,whoami,4,Technique,2.0,r,0\n"+
		"T1082,sysinfo,4,Technique,1.0,r,0\n"+
		"T1057,proc,4,Technique,1.0,r,0\n"+
		"T1016,netcfg,4,Technique,1.0,r,0\n")
	last := mustSummarise(t, "live-20260726-b.csv", header+
		// 共通4技は Tactic 以上を維持(ランクは下がっても検知は継続)
		"T1033,whoami,3,Tactic,2.0,r,0\n"+
		"T1082,sysinfo,4,Technique,1.0,r,0\n"+
		"T1057,proc,3,Tactic,2.0,r,0\n"+
		"T1016,netcfg,3,Tactic,1.0,r,0\n"+
		// 新規に計測対象へ加えた難しい技法(未検知)
		"T1486,ransom,0,None,,,0\n"+
		"T1110,brute,0,None,,,0\n")

	// 全体率では 100% → 66.7% と落ちて見える(=旧ロジックが誤検出した値)
	if last.DetectionPct != 66.7 {
		t.Fatalf("前提が崩れている: last.DetectionPct = %.1f, want 66.7", last.DetectionPct)
	}
	msg, regressed := checkRegression([]*Summary{prev, last}, 0, 3)
	if regressed {
		t.Errorf("母集団の拡大を回帰と判定した: %s", msg)
	}
}

// 共通技法の中で本当に検知が落ちたら、母集団が同じでも違っても検出すること。
func TestCheckRegression_RealDropDetected(t *testing.T) {
	prev := mustSummarise(t, "live-20260702-a.csv", header+
		"T1033,whoami,4,Technique,2.0,r,0\n"+
		"T1082,sysinfo,4,Technique,1.0,r,0\n"+
		"T1057,proc,4,Technique,1.0,r,0\n"+
		"T1016,netcfg,4,Technique,1.0,r,0\n")
	last := mustSummarise(t, "live-20260726-b.csv", header+
		"T1033,whoami,4,Technique,2.0,r,0\n"+
		"T1082,sysinfo,4,Technique,1.0,r,0\n"+
		"T1057,proc,0,None,,,0\n"+ // 検知が消えた = 本物の回帰
		"T1016,netcfg,4,Technique,1.0,r,0\n")

	msg, regressed := checkRegression([]*Summary{prev, last}, 0, 3)
	if !regressed {
		t.Errorf("共通technique上の検知低下を見逃した: %s", msg)
	}
}

// 同じプラットフォームでも共通技法が少なすぎるときは判定しない。
func TestCheckRegression_SkipsWhenCohortTooSmall(t *testing.T) {
	prev := mustSummarise(t, "live-20260702-linux-a.csv", header+
		"T1059.004,bash,4,Technique,1.0,r,0\n"+
		"T1003.008,shadow,4,Technique,1.0,r,0\n")
	last := mustSummarise(t, "live-20260726-linux-b.csv", header+
		"T1486,ransom,0,None,,,0\n"+
		"T1110,brute,0,None,,,0\n")

	msg, regressed := checkRegression([]*Summary{prev, last}, 0, 3)
	if regressed {
		t.Errorf("共通technique 0 件なのに回帰判定した: %s", msg)
	}
	if !strings.Contains(msg, "スキップ") {
		t.Errorf("スキップした旨を報告すべき: %q", msg)
	}
}

// 直前の実行が別 OS でも、同じプラットフォームの前回まで遡って比較すること。
// 単純に1つ前を取ると OS 跨ぎの比較になり、共通 technique がほぼ無いので
// ゲートが毎回スキップされて実質無効化される。
func TestCheckRegression_ComparesAgainstSamePlatform(t *testing.T) {
	winOld := mustSummarise(t, "live-20260702-windows-discovery.csv", header+
		"T1033,a,4,Technique,1.0,r,0\n"+
		"T1082,b,4,Technique,1.0,r,0\n"+
		"T1057,c,4,Technique,1.0,r,0\n"+
		"T1016,d,4,Technique,1.0,r,0\n")
	// 間に挟まる Linux 実行。ここと比べても共通 technique はゼロ。
	linux := mustSummarise(t, "live-20260710-linux-fullchain.csv", header+
		"T1059.004,bash,4,Technique,1.0,r,0\n"+
		"T1003.008,shadow,4,Technique,1.0,r,0\n")
	winNew := mustSummarise(t, "live-20260726-windows-scorecard.csv", header+
		"T1033,a,4,Technique,1.0,r,0\n"+
		"T1082,b,4,Technique,1.0,r,0\n"+
		"T1057,c,0,None,,,0\n"+ // Windows 系列で本物の低下
		"T1016,d,4,Technique,1.0,r,0\n")

	msg, regressed := checkRegression([]*Summary{winOld, linux, winNew}, 0, 3)
	if !regressed {
		t.Errorf("同一プラットフォーム(windows)の前回と比較して回帰を検出すべき: %s", msg)
	}
	if !strings.Contains(msg, "live-20260702-windows-discovery.csv") {
		t.Errorf("比較相手は直前のLinuxではなく前回のWindowsであるべき: %q", msg)
	}
}

// そのプラットフォームの初回計測は、比較相手が無いので判定しない。
func TestCheckRegression_SkipsFirstRunOfPlatform(t *testing.T) {
	win := mustSummarise(t, "live-20260702-windows-a.csv", header+
		"T1033,a,4,Technique,1.0,r,0\n"+
		"T1082,b,4,Technique,1.0,r,0\n"+
		"T1057,c,4,Technique,1.0,r,0\n")
	linuxFirst := mustSummarise(t, "live-20260726-linux-first.csv", header+
		"T1059.004,bash,0,None,,,0\n"+
		"T1003.008,shadow,0,None,,,0\n"+
		"T1053.003,cron,0,None,,,0\n")

	msg, regressed := checkRegression([]*Summary{win, linuxFirst}, 0, 3)
	if regressed {
		t.Errorf("linux の初回計測を回帰と判定した: %s", msg)
	}
	if !strings.Contains(msg, "linux") {
		t.Errorf("どのプラットフォームの過去実行が無いのか示すべき: %q", msg)
	}
}

// 許容 pt 内の低下は回帰としない。
func TestCheckRegression_WithinTolerance(t *testing.T) {
	prev := mustSummarise(t, "live-20260702-a.csv", header+
		"T1033,a,4,Technique,1.0,r,0\n"+
		"T1082,b,4,Technique,1.0,r,0\n"+
		"T1057,c,4,Technique,1.0,r,0\n"+
		"T1016,d,4,Technique,1.0,r,0\n")
	last := mustSummarise(t, "live-20260726-b.csv", header+
		"T1033,a,4,Technique,1.0,r,0\n"+
		"T1082,b,4,Technique,1.0,r,0\n"+
		"T1057,c,4,Technique,1.0,r,0\n"+
		"T1016,d,0,None,,,0\n") // 4技中1技落ち = 25pt 低下

	if _, regressed := checkRegression([]*Summary{prev, last}, 30, 3); regressed {
		t.Error("許容 30pt に対し 25pt 低下は回帰としないべき")
	}
	if _, regressed := checkRegression([]*Summary{prev, last}, 20, 3); !regressed {
		t.Error("許容 20pt に対し 25pt 低下は回帰とすべき")
	}
}

// 読めなかったファイルがある場合、その事実が Markdown 上に必ず出ること。
// 黙って捨てると「最新の実行が欠けたまま古い2件で判定して緑」に気づけない。
func TestRenderMarkdown_ShowsUnreadableNote(t *testing.T) {
	s := mustSummarise(t, "live-20260726-b.csv", header+"T1033,a,4,Technique,1.0,r,0\n")
	notes := []string{
		"**読めなかったスコアカード 1/2 件: live-20260801-broken.csv** — この分は集計にも回帰判定にも入っていません。",
		"回帰判定スキップ: 母集団が異なるため比較しません。",
	}
	md := renderMarkdown([]*Summary{s}, notes)
	for _, want := range []string{"live-20260801-broken.csv", "読めなかったスコアカード", "回帰判定スキップ"} {
		if !strings.Contains(md, want) {
			t.Errorf("Markdown に %q が含まれていない:\n%s", want, md)
		}
	}
}

// 注記が無いときは注記ブロックごと出さない(表だけ)。
func TestRenderMarkdown_NoNotes(t *testing.T) {
	s := mustSummarise(t, "live-20260726-b.csv", header+"T1033,a,4,Technique,1.0,r,0\n")
	md := renderMarkdown([]*Summary{s}, nil)
	if strings.Contains(md, ">") {
		t.Errorf("注記が無いのに引用ブロックが出ている:\n%s", md)
	}
}

func TestCheckRegression_SingleRunIsQuiet(t *testing.T) {
	only := mustSummarise(t, "live-20260726-b.csv", header+"T1033,a,4,Technique,1.0,r,0\n")
	msg, regressed := checkRegression([]*Summary{only}, 0, 3)
	if regressed || msg != "" {
		t.Errorf("実行が1件だけなら判定しない: msg=%q regressed=%v", msg, regressed)
	}
}
