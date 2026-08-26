package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// baseT は採点テストの基準時刻(各実行の開始)。
var baseT = time.Date(2026, 6, 21, 10, 0, 0, 0, time.UTC)

func ptr(s string) *string { return &s }

// mkAlert は指定オフセット(秒)・technique のアラートを生成する。
func mkAlert(id, tech string, offsetSec int, agent string) Alert {
	a := Alert{
		ID:        id,
		AgentID:   agent,
		Title:     "test alert " + id,
		CreatedAt: baseT.Add(time.Duration(offsetSec) * time.Second),
	}
	if tech != "" {
		a.Mitre = ptr(tech)
	}
	return a
}

// eventsServer は /api/v1/events に固定の total を返し、/api/v1/alerts は空を返す
// httptest サーバを起動して client を返す。score() のテレメトリ経路検証用。
func newEventsClient(t *testing.T, eventsTotal int) *client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		total := 0
		if strings.Contains(r.URL.Path, "/events") {
			total = eventsTotal
		}
		_ = json.NewEncoder(w).Encode(listResp{Data: json.RawMessage("[]"), Total: total})
	}))
	t.Cleanup(srv.Close)
	return &client{base: srv.URL, token: "tok", hc: srv.Client()}
}

func TestScore_Categories(t *testing.T) {
	run := func(tech string) runEntry {
		return runEntry{Technique: tech, Start: baseT, End: baseT.Add(3 * time.Second)}
	}
	win := 60 * time.Second // 検知窓 = [start, end+60s] = [+0s, +63s]

	tests := []struct {
		name        string
		run         runEntry
		alerts      []Alert
		eventsTotal int
		wantRank    int
		wantLatency float64 // 秒。-1 は未検知
	}{
		{
			name:        "Technique: 完全一致",
			run:         run("T1059.001"),
			alerts:      []Alert{mkAlert("a1", "T1059.001", 5, "")},
			wantRank:    rankTechnique,
			wantLatency: 5,
		},
		{
			name:        "Technique: 親子(基底)一致 T1059 vs T1059.001",
			run:         run("T1059.001"),
			alerts:      []Alert{mkAlert("a1", "T1059", 4, "")},
			wantRank:    rankTechnique,
			wantLatency: 4,
		},
		{
			name:        "Tactic: 別technique同tactic(execution) T1203 vs T1059.001",
			run:         run("T1059.001"),
			alerts:      []Alert{mkAlert("a1", "T1203", 10, "")},
			wantRank:    rankTactic,
			wantLatency: 10,
		},
		{
			name:        "背景アラート(MITRE無し)は加点しない→None",
			run:         run("T1003.001"),
			alerts:      []Alert{mkAlert("a1", "", 7, "")},
			wantRank:    rankNone,
			wantLatency: -1,
		},
		{
			name:        "無関係(tactic非共有 T1490 vs T1003.001)は加点しない→None",
			run:         run("T1003.001"),
			alerts:      []Alert{mkAlert("a1", "T1490", 6, "")},
			wantRank:    rankNone,
			wantLatency: -1,
		},
		{
			name:        "Telemetry: アラート無し+events有り",
			run:         run("T1059.001"),
			alerts:      nil,
			eventsTotal: 3,
			wantRank:    rankTelemetry,
			wantLatency: -1,
		},
		{
			name:        "None: アラートもeventsも無し",
			run:         run("T1059.001"),
			alerts:      nil,
			eventsTotal: 0,
			wantRank:    rankNone,
			wantLatency: -1,
		},
		{
			name:        "窓外アラートは無視され None に落ちる",
			run:         run("T1059.001"),
			alerts:      []Alert{mkAlert("a1", "T1059.001", 120, "")}, // +120s > winEnd(+63s)
			eventsTotal: 0,
			wantRank:    rankNone,
			wantLatency: -1,
		},
		{
			name:        "実行開始より前の単一技アラートは無視(前方窓のみ)",
			run:         run("T1059.001"),
			alerts:      []Alert{mkAlert("a1", "T1059.001", -10, "")},
			eventsTotal: 0,
			wantRank:    rankNone,
			wantLatency: -1,
		},
		{
			// 相関アラート(>1技=偵察バースト等)は run の前 win 以内に発火しても加点する。
			// バーストが早期発火し直後に走った net localgroup(T1069.001) を救済するケース。
			name: "相関アラートは実行前(win以内)でも加点(双方向)",
			run:  run("T1069.001"),
			alerts: []Alert{{
				ID: "burst", CreatedAt: baseT.Add(-10 * time.Second),
				Mitre: ptr("T1033"), AIMitreTags: []string{"T1057", "T1069.001"},
			}},
			eventsTotal: 0,
			wantRank:    rankTechnique,
			wantLatency: -1, // 発火が run 開始前なので latency は記録されない(>=0 のみ)
		},
		{
			name: "複数アラート: 最良ランクと最短レイテンシを採用",
			run:  run("T1059.001"),
			alerts: []Alert{
				mkAlert("a1", "T1203", 8, ""),      // tactic一致 rank3, lat8
				mkAlert("a2", "T1059.001", 12, ""), // technique一致 rank4, lat12
			},
			wantRank:    rankTechnique,
			wantLatency: 8, // General以上の最短(8s)
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := newEventsClient(t, tc.eventsTotal)
			got := c.attribute([]runEntry{tc.run}, tc.alerts, win, "")[0]
			if got.rank != tc.wantRank {
				t.Errorf("rank = %d(%s), want %d(%s)",
					got.rank, rankName[got.rank], tc.wantRank, rankName[tc.wantRank])
			}
			gotLat := -1.0
			if got.latency >= 0 {
				gotLat = got.latency.Seconds()
			}
			if gotLat != tc.wantLatency {
				t.Errorf("latency = %.0f, want %.0f", gotLat, tc.wantLatency)
			}
		})
	}
}

// agentID フィルタで他エージェントのアラートが除外されることを確認。
func TestScore_AgentFilter(t *testing.T) {
	c := newEventsClient(t, 0)
	run := runEntry{Technique: "T1059.001", Start: baseT, End: baseT.Add(3 * time.Second)}
	alerts := []Alert{
		mkAlert("a1", "T1059.001", 5, "other-agent"),
		mkAlert("a2", "T1059.001", 6, "target-agent"),
	}
	got := c.attribute([]runEntry{run}, alerts, 60*time.Second, "target-agent")[0]
	if got.rank != rankTechnique {
		t.Fatalf("rank = %s, want Technique", rankName[got.rank])
	}
	if got.latency.Seconds() != 6 {
		t.Errorf("latency = %.0f, want 6 (other-agent の 5s は除外されるべき)", got.latency.Seconds())
	}
}

// ai_mitre_tags 経由でも technique 一致できることを確認。
func TestScore_AIMitreTags(t *testing.T) {
	c := newEventsClient(t, 0)
	run := runEntry{Technique: "T1003.001", Start: baseT, End: baseT.Add(3 * time.Second)}
	a := Alert{ID: "a1", CreatedAt: baseT.Add(5 * time.Second),
		AIMitreTags: []string{"attack.t1003.001", "attack.credential_access"}}
	got := c.attribute([]runEntry{run}, []Alert{a}, 60*time.Second, "")[0]
	if got.rank != rankTechnique {
		t.Fatalf("rank = %s, want Technique (ai_mitre_tags 経由)", rankName[got.rank])
	}
}

// fetchAlerts が has_more を辿って全ページ取得することを確認。
func TestFetchAlerts_Pagination(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("page")
		var body listResp
		switch page {
		case "1":
			body = listResp{Data: json.RawMessage(`[{"id":"a1","mitre_technique":"T1059.001"}]`), Total: 2, HasMore: true}
		default:
			body = listResp{Data: json.RawMessage(`[{"id":"a2","mitre_technique":"T1490"}]`), Total: 2, HasMore: false}
		}
		_ = json.NewEncoder(w).Encode(body)
	}))
	defer srv.Close()
	c := &client{base: srv.URL, token: "tok", hc: srv.Client()}

	alerts, err := c.fetchAlerts(baseT, baseT.Add(time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 2 {
		t.Fatalf("取得 %d 件, want 2 (ページング失敗)", len(alerts))
	}
	if alerts[0].ID != "a1" || alerts[1].ID != "a2" {
		t.Errorf("順序/内容不正: %+v", alerts)
	}
}

// getJSON が非200を明確なエラーとして返すことを確認。
func TestGetJSON_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()
	c := &client{base: srv.URL, token: "bad", hc: srv.Client()}
	var lr listResp
	err := c.getJSON("/api/v1/alerts", nil, &lr)
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("401 エラーが伝播していない: %v", err)
	}
}

func TestLoadRunlog(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "runlog.csv")
	// 列順を入れ替え、test_name/exit_code を後方に配置(ヘッダ解決を検証)。
	content := "start_utc,end_utc,technique,test_name,exit_code\n" +
		"2026-06-21T10:05:00Z,2026-06-21T10:05:04Z,t1003.001,LSASS,0\n" +
		"2026-06-21T10:00:00Z,2026-06-21T10:00:03Z,T1059.001,PowerShell,0\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	runs, err := loadRunlog(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 2 {
		t.Fatalf("entries = %d, want 2", len(runs))
	}
	// Start 昇順にソートされ、technique は大文字化される。
	if runs[0].Technique != "T1059.001" {
		t.Errorf("先頭 technique = %q, want T1059.001 (時刻ソート)", runs[0].Technique)
	}
	if runs[1].Technique != "T1003.001" {
		t.Errorf("2件目 technique = %q, want T1003.001 (小文字入力の大文字化)", runs[1].Technique)
	}
}

func TestLoadRunlog_MissingColumn(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.csv")
	if err := os.WriteFile(path, []byte("technique,start_utc\nT1059,2026-06-21T10:00:00Z\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadRunlog(path); err == nil || !strings.Contains(err.Error(), "end_utc") {
		t.Fatalf("end_utc 欠落を検出できていない: %v", err)
	}
}

func TestLoadRunlog_ScenarioColumn(t *testing.T) {
	dir := t.TempDir()
	// scenario 列なし → Scenario は空であるべき(欠落任意列が列0=technique を
	// 誤取得して誤チェーン採点になる回帰のガード)。
	p1 := filepath.Join(dir, "noscenario.csv")
	if err := os.WriteFile(p1, []byte(
		"technique,test_name,start_utc,end_utc,exit_code\n"+
			"T1059.001,ps,2026-06-21T10:00:00Z,2026-06-21T10:00:03Z,0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runs, err := loadRunlog(p1)
	if err != nil {
		t.Fatal(err)
	}
	if runs[0].Scenario != "" {
		t.Errorf("scenario列なしの Scenario = %q, want \"\"(技術名を誤取得していないか)", runs[0].Scenario)
	}
	// scenario 列あり → 反映される。
	p2 := filepath.Join(dir, "scenario.csv")
	if err := os.WriteFile(p2, []byte(
		"technique,start_utc,end_utc,scenario\n"+
			"T1566.001,2026-06-21T10:00:00Z,2026-06-21T10:00:03Z,intrusion-chain\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runs2, err := loadRunlog(p2)
	if err != nil {
		t.Fatal(err)
	}
	if runs2[0].Scenario != "intrusion-chain" {
		t.Errorf("scenario = %q, want intrusion-chain", runs2[0].Scenario)
	}
}

func TestOfflineScoring(t *testing.T) {
	dir := t.TempDir()
	af := filepath.Join(dir, "alerts.json")
	// live API と同じスキーマ。a1=mitre_technique, a2=ai_mitre_tags。
	js := `[
      {"id":"a1","mitre_technique":"T1059.001","title":"ps","created_at":"2026-06-21T10:00:02Z"},
      {"id":"a2","ai_mitre_tags":["T1003.001"],"title":"cred","created_at":"2026-06-21T10:00:02Z"}
    ]`
	if err := os.WriteFile(af, []byte(js), 0o644); err != nil {
		t.Fatal(err)
	}
	alerts, err := loadAlertsFile(af)
	if err != nil || len(alerts) != 2 {
		t.Fatalf("loadAlertsFile: err=%v len=%d", err, len(alerts))
	}
	if alerts[0].Mitre == nil || *alerts[0].Mitre != "T1059.001" {
		t.Fatalf("mitre_technique が解析されていない: %+v", alerts[0])
	}

	// オフライン採点: countEvents がスキップされ、未一致は Telemetry でなく None。
	c := &client{offline: true}
	run := func(tech string) runEntry {
		return runEntry{Technique: tech, Start: baseT, End: baseT.Add(3 * time.Second)}
	}
	res := c.attribute([]runEntry{run("T1059.001"), run("T1003.001"), run("T1490")}, alerts, 60*time.Second, "")
	if res[0].rank != rankTechnique {
		t.Errorf("T1059.001 は Technique であるべき, got %s", rankName[res[0].rank])
	}
	if res[1].rank != rankTechnique {
		t.Errorf("T1003.001 (ai_mitre_tags) は Technique であるべき, got %s", rankName[res[1].rank])
	}
	if res[2].rank != rankNone {
		t.Errorf("未一致はオフラインで None であるべき(events 判定スキップ), got %s", rankName[res[2].rank])
	}
}

func TestLoadAlertsFile_BadJSON(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(p, []byte("{not an array"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAlertsFile(p); err == nil {
		t.Fatal("不正JSONはエラーになるべき")
	}
}

func TestParseTime(t *testing.T) {
	cases := map[string]bool{
		"2026-06-21T10:00:00Z":      true,
		"2026-06-21T10:00:00+09:00": true,
		"2026-06-21 10:00:00":       true, // TZ無し → UTC扱い
		"not-a-time":                false,
		"":                          false,
	}
	for in, ok := range cases {
		_, err := parseTime(in)
		if ok && err != nil {
			t.Errorf("parseTime(%q) 失敗すべきでない: %v", in, err)
		}
		if !ok && err == nil {
			t.Errorf("parseTime(%q) 失敗すべき", in)
		}
	}
}

func TestTacticHelpers(t *testing.T) {
	if !sameTechnique("T1059.001", "T1059") {
		t.Error("sameTechnique(T1059.001,T1059) should be true")
	}
	if sameTechnique("T1059.001", "T1003.001") {
		t.Error("sameTechnique 別ファミリは false であるべき")
	}
	if !shareTactic("T1059.001", "T1203") { // ともに execution
		t.Error("shareTactic(execution同士) should be true")
	}
	if shareTactic("T1003.001", "T1490") { // credential-access vs impact
		t.Error("shareTactic 異tactic は false であるべき")
	}
	if len(tacticsOf("T9999")) != 0 {
		t.Error("未知 technique の tactic は空であるべき")
	}

	// サブテク精密マッチ(MITRE Evals 流): 同一基底でも別サブテクは Technique 一致しない。
	if sameTechnique("T1059.001", "T1059.003") {
		t.Error("別サブテク(T1059.001 vs .003)は誤特定 → sameTechnique=false であるべき")
	}
	if !sameTechnique("T1003.001", "T1003.001") {
		t.Error("完全一致サブテクは true であるべき")
	}
	if !sameTechnique("T1003", "T1003.001") {
		t.Error("基底 vs サブテク(片側が基底)は true であるべき")
	}
	// 別サブテク同士でも tactic は共有する(Tactic 止まりの加点経路)。
	if !shareTactic("T1059.001", "T1059.003") {
		t.Error("同一基底の別サブテクは同 tactic を共有(shareTactic=true)であるべき")
	}

	// 拡充した technique→tactic マップの代表例(実測で欠落していた discovery 群等)。
	for tech, want := range map[string]string{
		"T1069": "discovery", "T1049": "discovery", "T1007": "discovery",
		"T1012": "discovery", "T1135": "discovery", "T1482": "discovery",
		"T1140": "defense-evasion", "T1041": "exfiltration", "T1047": "execution",
		"T1021": "lateral-movement", "T1190": "initial-access",
	} {
		ts := tacticsOf(tech)
		found := false
		for _, x := range ts {
			if x == want {
				found = true
			}
		}
		if !found {
			t.Errorf("tacticsOf(%s) は %q を含むべき, got %v", tech, want, ts)
		}
	}
}

// 採点全体を1本通し、KPI 集計が妥当かをスモークする。
func TestEndToEndScorecardCounts(t *testing.T) {
	c := newEventsClient(t, 1) // events 常に1件 → アラート無しは Telemetry
	win := 60 * time.Second
	runs := []runEntry{
		{Technique: "T1059.001", Start: baseT, End: baseT.Add(2 * time.Second)},
		{Technique: "T1490", Start: baseT.Add(time.Minute), End: baseT.Add(time.Minute + 2*time.Second)},
	}
	alerts := []Alert{
		mkAlert("a1", "T1059.001", 3, ""), // 1件目 → Technique
		// 2件目(T1490)に対応するアラート無し → events有りで Telemetry
	}
	results := c.attribute(runs, alerts, win, "")
	if results[0].rank != rankTechnique {
		t.Errorf("run0 rank = %s, want Technique", rankName[results[0].rank])
	}
	if results[1].rank != rankTelemetry {
		t.Errorf("run1 rank = %s, want Telemetry", rankName[results[1].rank])
	}
	// pct ヘルパの整合(2件中1件 Technique = 50%)。
	if got := pct(1, 2); !strings.Contains(got, "50.0%") {
		t.Errorf("pct(1,2) = %q, want 50.0%% を含む", got)
	}
	fmt.Fprintln(os.Stderr, "end-to-end scorecard OK")
}

// shortRef はスコアカード CSV の matched_by 列を作る。バイト数で切ると日本語の
// ルール名(状態付き検知器は日本語タイトルを出す)が UTF-8 の途中で分断され、
// 出力 CSV が不正なバイト列になる。Windows 実機の計測は英語ルール名ばかりで
// 表面化せず、Linux 実機を初めて CI から測った 2026-08-05 に露見した。
func TestShortRef_MultibyteTruncation(t *testing.T) {
	cases := []struct {
		name  string
		title string
	}{
		{"日本語の長いタイトル", "[BEHAVIORAL] 探索コマンドの短時間バーストを検知しました。連続した情報収集の兆候があります"},
		{"ASCIIの長いタイトル", "[Sigma] " + strings.Repeat("System Information Recon Command Execution ", 3)},
		{"境界(48ルーン超)", strings.Repeat("あ", 49)},
		{"境界(48ルーン)", strings.Repeat("あ", 48)},
		{"短いタイトル", "[IOC] short"},
		{"空", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := shortRef(Alert{Title: tc.title, ID: "9fbd269d-881f-41e3-85c5-92dd48ba7418"})
			if !utf8.ValidString(got) {
				t.Errorf("shortRef が不正な UTF-8 を返した: %q", got)
			}
			if !strings.Contains(got, "9fbd269d-881f-41e3-85c5-92dd48ba7418") {
				t.Errorf("アラートIDが欠落した: %q", got)
			}
			// 48ルーン以下なら切り詰めない。
			if utf8.RuneCountInString(tc.title) <= 48 && strings.Contains(got, "…") {
				t.Errorf("切り詰め不要なのに省略記号が付いた: %q", got)
			}
			if utf8.RuneCountInString(tc.title) > 48 && !strings.Contains(got, "…") {
				t.Errorf("切り詰められていない: %q", got)
			}
		})
	}
}
