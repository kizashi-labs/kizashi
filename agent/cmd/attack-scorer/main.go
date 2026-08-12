// Command attack-scorer は Atomic Red Team 等で実行した ATT&CK テクニックの
// 実行ログ(runlog CSV)と、Kizashi サーバの alerts/events を時間窓で突合し、
// MITRE ATT&CK Evaluations 準拠の検知カテゴリ(None/Telemetry/General/Tactic/
// Technique)を付与して検知率スコアカードを算出する自己測定ツールである。
//
// 使い方:
//
//	attack-scorer \
//	  -server https://<host> \
//	  -token  <JWT または edr_ APIキー> \
//	  -runlog runlog.csv \
//	  [-agent <agent_id でフィルタ>] \
//	  [-window 120]        実行終了から検知を許容する秒数(既定120)
//	  [-out scorecard.csv] \
//	  [-insecure]          TLS 検証をスキップ(検証環境のみ)
//
// runlog.csv の想定ヘッダ(順不同・大文字小文字無視):
//
//	technique,test_name,start_utc,end_utc,exit_code
//
// start_utc / end_utc は RFC3339 (UTC) 文字列。付属の run-atomics.ps1 が
// この形式で出力する。詳細は docs/ATT&CK検知率測定計画.md を参照。
package main

import (
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// 検知カテゴリ(ランク)。値が大きいほど高評価。
const (
	rankNone      = 0 // 何も残らない
	rankTelemetry = 1 // 生イベントは残ったがアラート化されず
	rankGeneral   = 2 // アラート化したが technique 未特定
	rankTactic    = 3 // tactic レベルまで特定
	rankTechnique = 4 // technique ID まで特定
)

var rankName = map[int]string{
	rankNone: "None", rankTelemetry: "Telemetry", rankGeneral: "General",
	rankTactic: "Tactic", rankTechnique: "Technique",
}

// Alert はサーバ /api/v1/alerts のレスポンス要素(必要フィールドのみ)。
type Alert struct {
	ID            string    `json:"id"`
	AgentID       string    `json:"agent_id"`
	AgentHostname string    `json:"agent_hostname"`
	Severity      int       `json:"severity"`
	Title         string    `json:"title"`
	Description   string    `json:"description"`
	Mitre         *string   `json:"mitre_technique"`
	AIMitreTags   []string  `json:"ai_mitre_tags"`
	CreatedAt     time.Time `json:"created_at"`
}

// blockMarkers are substrings that mark an alert as a PREVENTION (the technique
// was blocked/denied), not just detected — used for the Protection axis. Drawn
// from the actual enforce-path alert text: eBPF LSM exec deny ("実行を拒否",
// "-EPERM"), Windows driver tamper/cred strip ("拒否", "剥奪", "阻止"), and the
// generic block verdicts.
var blockMarkers = []string{
	"拒否", "阻止", "剥奪", "-EPERM", "access denied", "blocked", "prevented",
}

// isBlocking reports whether the alert represents a prevented (not merely
// detected) technique, for the Protection axis.
func (a Alert) isBlocking() bool {
	hay := strings.ToLower(a.Title + " " + a.Description)
	for _, m := range blockMarkers {
		if strings.Contains(hay, strings.ToLower(m)) {
			return true
		}
	}
	return false
}

// techniques はこのアラートが指している ATT&CK technique 候補をすべて返す
// (mitre_technique と ai_mitre_tags から "attack.t1059.001" / "T1059" 等の
// T番号を抽出して統合)。
func (a Alert) techniques() []string {
	var out []string
	if a.Mitre != nil {
		if c := extractTechnique(*a.Mitre); c != "" {
			out = append(out, c)
		}
	}
	for _, tag := range a.AIMitreTags {
		if c := extractTechnique(tag); c != "" {
			out = append(out, c)
		}
	}
	return out
}

// listResp は alerts/events 共通のページ付きレスポンスラッパー。
type listResp struct {
	Data    json.RawMessage `json:"data"`
	Total   int             `json:"total"`
	HasMore bool            `json:"has_more"`
}

// runEntry は runlog の1行 = 実行した1テクニック。
type runEntry struct {
	Technique string
	TestName  string
	Start     time.Time
	End       time.Time
	ExitCode  string
	Scenario  string // 任意: 同名の行を1つの多段攻撃チェーンとして採点する
}

type client struct {
	base    string
	token   string
	hc      *http.Client
	offline bool // -alerts 指定時: サーバへ問い合わせず events 判定をスキップ(Telemetry非区別)
}

func main() {
	var (
		server     = flag.String("server", "", "サーバのベースURL (例 https://host)")
		token      = flag.String("token", "", "JWT または edr_ APIキー")
		runlog     = flag.String("runlog", "", "Atomic 実行ログ CSV のパス")
		caldera    = flag.String("caldera", "", "Caldera オペレーションレポート JSON のパス(-runlog の代わり。多段エミュレーションをチェーン採点)")
		agentID    = flag.String("agent", "", "突合対象を絞るエージェントID(任意)")
		window     = flag.Int("window", 120, "実行終了から検知を許容する秒数")
		outPath    = flag.String("out", "scorecard.csv", "スコアカード CSV 出力先")
		insecure   = flag.Bool("insecure", false, "TLS 検証をスキップ(検証環境のみ)")
		baseline   = flag.String("baseline", "", "過去のスコアカードCSV。率がbaselineを下回ったら非ゼロ終了(定点観測/CI回帰ゲート)")
		baseTol    = flag.Float64("baseline-tol", 0, "許容する率低下(ポイント)。これを超える低下を回帰扱い")
		alertsFile = flag.String("alerts", "", "オフライン採点用アラートJSON(配列)。指定時は -server に問い合わせず fixture で採点(決定的・CI向け)")
	)
	flag.Parse()

	// 実行ログは -runlog(Atomic CSV) か -caldera(オペレーションレポート JSON) のどちらか必須。
	// オフライン採点(-alerts)時は server/token 不要、それ以外は必須。
	if (*runlog == "" && *caldera == "") || (*alertsFile == "" && (*server == "" || *token == "")) {
		fmt.Fprintln(os.Stderr, "必須: (-runlog <csv> | -caldera <report.json>) と (-server -token | -alerts <fixture.json>)")
		flag.Usage()
		os.Exit(2)
	}

	var runs []runEntry
	var err error
	if *caldera != "" {
		runs, err = loadCalderaReport(*caldera)
		if err != nil {
			fatal("Caldera レポート読み込み失敗: %v", err)
		}
	} else {
		runs, err = loadRunlog(*runlog)
		if err != nil {
			fatal("runlog 読み込み失敗: %v", err)
		}
	}
	if len(runs) == 0 {
		fatal("runlog にエントリがありません")
	}

	tr := &http.Transport{}
	if *insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 検証環境専用フラグ
	}
	c := &client{
		base:    strings.TrimRight(*server, "/"),
		token:   *token,
		hc:      &http.Client{Timeout: 30 * time.Second, Transport: tr},
		offline: *alertsFile != "",
	}

	// 測定全体の時間範囲 = 最初の実行開始 〜 最後の実行終了+window。
	win := time.Duration(*window) * time.Second
	from, to := runs[0].Start, runs[0].End.Add(win)
	for _, r := range runs {
		if r.Start.Before(from) {
			from = r.Start
		}
		if e := r.End.Add(win); e.After(to) {
			to = e
		}
	}

	// アラート取得: -alerts 指定時は fixture(オフライン)、そうでなければサーバから一括取得。
	var alerts []Alert
	if *alertsFile != "" {
		alerts, err = loadAlertsFile(*alertsFile)
		if err != nil {
			fatal("alerts fixture 読み込み失敗: %v", err)
		}
		fmt.Fprintf(os.Stderr, "オフライン採点: alerts fixture %s (%d 件)\n", *alertsFile, len(alerts))
	} else {
		alerts, err = c.fetchAlerts(from, to, *agentID)
		if err != nil {
			fatal("alerts 取得失敗: %v", err)
		}
		fmt.Fprintf(os.Stderr, "取得アラート: %d 件 (期間 %s 〜 %s)\n",
			len(alerts), from.Format(time.RFC3339), to.Format(time.RFC3339))
	}

	results := c.attribute(runs, alerts, win, *agentID)

	printScorecard(results, win)
	printChainScorecard(scoreChains(results))
	if err := writeScorecardCSV(*outPath, results); err != nil {
		fatal("スコアカード書き込み失敗: %v", err)
	}
	fmt.Fprintf(os.Stderr, "スコアカードCSV: %s\n", *outPath)

	// 定点観測: baseline が指定されたら率の低下を回帰として検出する。
	if *baseline != "" {
		base, err := loadBaselineKPI(*baseline)
		if err != nil {
			fatal("baseline 読み込み失敗: %v", err)
		}
		regressed, report := checkRegression(summarize(results), base, *baseTol)
		fmt.Println("\n" + report)
		if regressed {
			fmt.Fprintln(os.Stderr, "回帰を検出しました(率が baseline を許容幅超で下回りました)")
			os.Exit(3)
		}
	}
}

// result は1テクニックの採点結果。
type result struct {
	run       runEntry
	rank      int
	matchedBy string        // 一致したアラートのID/タイトル(根拠)
	latency   time.Duration // 実行開始→最初の検知アラートまで。未検知は -1
	blocked   bool          // 一致アラートが防御で阻止(Protection軸)を示した
}

// attribute はアラート群をテクニック群へ突合し採点する。測定の厳密性のため:
//
//	① MITRE technique を持たないアラート（UEBA「異常プロセス」等の背景アラート）は採点しない。
//	   ＝ 「窓内に何かアラートがある」だけの General 判定は廃止し、technique/tactic 一致のみ検知とみなす。
//	② 各アラートは「一致しかつ最も直近に開始したテクニック」へ一意に attribute する。
//	   ＝ 1つのアラートが（窓の重複で）複数テクニックを水増しすることを防ぐ。
//
// 一致無しのテクニックは events のテレメトリ有無で Telemetry/None 判定。
func (c *client) attribute(runs []runEntry, alerts []Alert, win time.Duration, agentID string) []result {
	res := make([]result, len(runs))
	for i := range runs {
		res[i] = result{run: runs[i], rank: rankNone, latency: -1}
	}

	for _, a := range alerts {
		if agentID != "" && a.AgentID != agentID {
			continue
		}
		ats := a.techniques()
		if len(ats) == 0 {
			continue // MITRE 無し＝背景アラート。どのテクニックにも加点しない。
		}
		// このアラートが ATT&CK タグで対応する全テクニックに加点する。1アラートが
		// 複数技を検知する相関アラート(偵察バースト等)を、検知窓内で実行された分
		// だけ正当に加点(MITRE Evals 流)。単一技ルールはタグが1つなので従来通り。
		// 過剰加点はしない: 加点対象は「runlog にあり ∧ アラートのタグに一致 ∧
		// 検知窓内」のテクニックのみ。
		// 下限境界: 単一技アラートは前方窓のみ(検知レイテンシ意味論=アラートは
		// アクションに先行しない)。相関アラート(>1 ATT&CK技、例 偵察バースト)は観測
		// *窓*を1アラートに畳み、閾値到達時に一度発火するため、同一セッション内で直後に
		// 走ったコマンド(例 net localgroup)が早期アラートの前方窓から漏れる。バーストは
		// discovery セッション全体を検知済み(全 discovery タグ保持)なので、run の前後
		// win 以内に発火した*相関*アラートを加点する(MITRE Evals 流=シナリオ中に技術を
		// 検知したか)。過剰加点防止: 単一技は従来通り前方のみ + 依然タグ一致が必須。
		lowerBound := func(r runEntry) time.Time {
			if len(ats) > 1 {
				return r.Start.Add(-win)
			}
			return r.Start
		}
		for i, r := range runs {
			if a.CreatedAt.Before(lowerBound(r)) || a.CreatedAt.After(r.End.Add(win)) {
				continue
			}
			cat := rankNone
			for _, at := range ats {
				if sameTechnique(at, r.Technique) {
					cat = rankTechnique
					break
				}
				if cat < rankTactic && shareTactic(at, r.Technique) {
					cat = rankTactic
				}
			}
			if cat == rankNone {
				continue // このアラートはこの run に無関係。
			}
			if cat > res[i].rank {
				res[i].rank = cat
				res[i].matchedBy = shortRef(a)
			}
			if a.isBlocking() {
				res[i].blocked = true // Protection: the technique was prevented, not just seen
			}
			// MTTD は非負のみ記録する。相関アラートを双方向加点する際、run 開始より
			// 前に発火したアラート(lat<0)は検知済みだが「行動→検知の遅延」としては
			// 意味を持たないため latency に含めない。
			if lat := a.CreatedAt.Sub(r.Start); lat >= 0 && (res[i].latency < 0 || lat < res[i].latency) {
				res[i].latency = lat
			}
		}
	}

	// 一致が無かったテクニックは events のテレメトリ有無で Telemetry/None。
	for i := range res {
		if res[i].rank != rankNone {
			continue
		}
		if n, err := c.countEvents(runs[i].Start, runs[i].End.Add(win), agentID); err == nil && n > 0 {
			res[i].rank = rankTelemetry
		}
	}
	return res
}

func shortRef(a Alert) string {
	t := a.Title
	// バイト数で切ると UTF-8 のマルチバイト文字が途中で分断され、出力 CSV に不正な
	// バイト列が混入する。サーバ側の状態付き検知器([BEHAVIORAL] 等)は日本語タイトルを
	// 出すため実際に壊れる(Windows 実機の計測は英語ルール名ばかりで表面化しなかった)。
	if r := []rune(t); len(r) > 48 {
		t = string(r[:48]) + "…"
	}
	return fmt.Sprintf("%s (%s)", t, a.ID)
}

// fetchAlerts は期間内アラートを has_more が尽きるまでページングして全件取得する。
func (c *client) fetchAlerts(from, to time.Time, agentID string) ([]Alert, error) {
	var all []Alert
	for page := 1; ; page++ {
		q := url.Values{}
		q.Set("from", from.Format(time.RFC3339))
		q.Set("to", to.Format(time.RFC3339))
		q.Set("per_page", "100")
		q.Set("page", strconv.Itoa(page))
		if agentID != "" {
			q.Set("agent_id", agentID)
		}
		var lr listResp
		if err := c.getJSON("/api/v1/alerts", q, &lr); err != nil {
			return nil, err
		}
		var batch []Alert
		if err := json.Unmarshal(lr.Data, &batch); err != nil {
			return nil, fmt.Errorf("alerts デコード: %w", err)
		}
		all = append(all, batch...)
		if !lr.HasMore || len(batch) == 0 {
			break
		}
	}
	return all, nil
}

// countEvents は期間内のイベント総数を返す(per_page=1 で total のみ参照)。
func (c *client) countEvents(from, to time.Time, agentID string) (int, error) {
	if c.offline {
		return 0, nil // オフライン採点: events fixture を持たないため Telemetry は区別しない
	}
	q := url.Values{}
	q.Set("from", from.Format(time.RFC3339))
	q.Set("to", to.Format(time.RFC3339))
	q.Set("per_page", "1")
	if agentID != "" {
		q.Set("agent_id", agentID)
	}
	var lr listResp
	if err := c.getJSON("/api/v1/events", q, &lr); err != nil {
		return 0, err
	}
	return lr.Total, nil
}

func (c *client) getJSON(path string, q url.Values, dst any) error {
	req, err := http.NewRequest(http.MethodGet, c.base+path+"?"+q.Encode(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return json.Unmarshal(body, dst)
}

// loadRunlog は runlog CSV を読む。ヘッダ名でカラムを解決するため列順は不問。
// loadAlertsFile はオフライン採点用のアラート fixture(JSON配列)を読む。
// 要素は live API と同じ Alert スキーマ(id/mitre_technique/ai_mitre_tags/created_at 等)。
// これにより runlog + alerts fixture で server 不要・決定的に採点でき、CI 定点観測に使える。
func loadAlertsFile(path string) ([]Alert, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var alerts []Alert
	if err := json.Unmarshal(b, &alerts); err != nil {
		return nil, fmt.Errorf("JSON 解析: %w", err)
	}
	return alerts, nil
}

func loadRunlog(path string) ([]runEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	rd := csv.NewReader(f)
	rd.FieldsPerRecord = -1
	rows, err := rd.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(rows) < 2 {
		return nil, fmt.Errorf("ヘッダ+1行以上が必要です")
	}

	idx := map[string]int{}
	for i, h := range rows[0] {
		idx[strings.ToLower(strings.TrimSpace(h))] = i
	}
	need := func(name string) (int, error) {
		if i, ok := idx[name]; ok {
			return i, nil
		}
		return -1, fmt.Errorf("runlog に列 %q がありません", name)
	}
	cTech, err := need("technique")
	if err != nil {
		return nil, err
	}
	cStart, err := need("start_utc")
	if err != nil {
		return nil, err
	}
	cEnd, err := need("end_utc")
	if err != nil {
		return nil, err
	}
	// 任意列は欠落時 -1 を返す(map のゼロ値 0 をそのまま使うと get() が列0=technique
	// を誤取得し、scenario 列の無い旧 runlog が Scenario=technique で誤チェーン採点に
	// なる)。get() は i<0 で "" を返す。
	opt := func(name string) int {
		if i, ok := idx[name]; ok {
			return i
		}
		return -1
	}
	cName := opt("test_name")    // 任意
	cExit := opt("exit_code")    // 任意
	cScenario := opt("scenario") // 任意: 多段チェーン採点用

	get := func(row []string, i int) string {
		if i >= 0 && i < len(row) {
			return strings.TrimSpace(row[i])
		}
		return ""
	}

	var out []runEntry
	for n, row := range rows[1:] {
		tech := get(row, cTech)
		if tech == "" {
			continue
		}
		st, err := parseTime(get(row, cStart))
		if err != nil {
			return nil, fmt.Errorf("%d 行目 start_utc: %w", n+2, err)
		}
		et, err := parseTime(get(row, cEnd))
		if err != nil {
			return nil, fmt.Errorf("%d 行目 end_utc: %w", n+2, err)
		}
		out = append(out, runEntry{
			Technique: strings.ToUpper(tech),
			TestName:  get(row, cName),
			Start:     st,
			End:       et,
			ExitCode:  get(row, cExit),
			Scenario:  get(row, cScenario),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Start.Before(out[j].Start) })
	return out, nil
}

// parseTime は RFC3339 を基本としつつ、タイムゾーン無しの "2006-01-02 15:04:05"
// (UTC とみなす) も受け付ける。
func parseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, fmt.Errorf("空")
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05Z07:00", "2006-01-02 15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("解析不能な時刻: %q", s)
}

// --- 出力 -------------------------------------------------------------------

// chainScore は1つの多段攻撃シナリオ(チェーン)の採点結果。ATT&CK Evaluations が
// 重視する「攻撃連鎖のどの段で可視化/検知できたか」を、単発テクニック採点の上に
// 集約する。実攻撃では1段でも検知できれば連鎖を断ち切れる(Broken)ため、段ごとの
// カバレッジと「最初に検知できた段」を併記する。
type chainScore struct {
	Scenario   string
	Steps      int    // 段数
	Visible    int    // rank>=Telemetry の段数(可視化軸)
	Detected   int    // rank>=Tactic の段数(検知軸 = スコアカードの検知率と同基準)
	Attributed int    // rank==Technique の段数(technique 特定)
	Protected  int    // 防御で阻止された段数(防御軸 = Protection)
	Broken     bool   // 1段以上検知 = 連鎖を断ち切れた
	FirstHit   string // 最初に検知できた段(TestName または Technique)
}

// scoreChains は per-technique の result を Scenario でグルーピングしチェーン採点する。
// Scenario が空の result はチェーン採点対象外(単発テクニック採点のみ)。results は
// 実行開始時刻順(loadRunlog がソート済)なので、各チェーンの FirstHit は最初に検知
// できた段になる。純関数 — サーバ/ネットワーク非依存でテスト可能。
func scoreChains(results []result) []chainScore {
	idx := map[string]int{}
	var chains []chainScore
	for _, r := range results {
		s := r.run.Scenario
		if s == "" {
			continue
		}
		i, ok := idx[s]
		if !ok {
			i = len(chains)
			idx[s] = i
			chains = append(chains, chainScore{Scenario: s})
		}
		c := &chains[i]
		c.Steps++
		if r.rank >= rankTelemetry {
			c.Visible++
		}
		if r.rank >= rankTactic {
			c.Detected++
			if !c.Broken {
				c.Broken = true
				if c.FirstHit = r.run.TestName; c.FirstHit == "" {
					c.FirstHit = r.run.Technique
				}
			}
		}
		if r.rank >= rankTechnique {
			c.Attributed++
		}
		if r.blocked {
			c.Protected++
		}
	}
	return chains
}

// printChainScorecard は多段チェーン採点を出力する。
func printChainScorecard(chains []chainScore) {
	if len(chains) == 0 {
		return
	}
	fmt.Println()
	fmt.Println("=== 多段攻撃チェーン採点 (ATT&CK Evaluations 形式) ===")
	broken := 0
	for _, c := range chains {
		status := "未検知（連鎖を許した）"
		if c.Broken {
			broken++
			status = "断ち切り（最初の検知: " + c.FirstHit + "）"
		}
		fmt.Printf("  [%s] 段数=%d 可視化=%d 検知=%d technique特定=%d 防御=%d → %s\n",
			c.Scenario, c.Steps, c.Visible, c.Detected, c.Attributed, c.Protected, status)
	}
	fmt.Printf("  チェーン断ち切り率: %d/%d\n", broken, len(chains))
	fmt.Println("  ※ 3軸: 可視化(Visibility)=テレメトリ有 / 検知(Detection)=アラート化 / 防御(Protection)=enforce阻止。")
}

func printScorecard(results []result, win time.Duration) {
	n := len(results)
	var vis, det, ana int
	var lats []time.Duration
	for _, r := range results {
		if r.rank >= rankTelemetry {
			vis++
		}
		if r.rank >= rankGeneral {
			det++
		}
		if r.rank >= rankTechnique {
			ana++
		}
		if r.latency >= 0 {
			lats = append(lats, r.latency)
		}
	}

	fmt.Println("=== Kizashi ATT&CK 検知率スコアカード ===")
	fmt.Printf("対象テクニック: %d / 許容検知窓: %s\n\n", n, win)
	fmt.Printf("  可視性率 (rank>=Telemetry)    : %s\n", pct(vis, n))
	fmt.Printf("  検知率   (Tactic+Technique)   : %s\n", pct(det, n))
	fmt.Printf("  解析検知 (Technique のみ)      : %s\n", pct(ana, n))
	if md := median(lats); md >= 0 {
		fmt.Printf("  MTTD (中央値)             : %.0fs (検知 %d/%d 件)\n", md.Seconds(), len(lats), n)
	} else {
		fmt.Printf("  MTTD (中央値)             : 検知0件\n")
	}

	fmt.Println("\n--- 個別結果 ---")
	for _, r := range results {
		ref := r.matchedBy
		if ref == "" {
			ref = "-"
		}
		fmt.Printf("  %-12s %-10s %s\n", r.run.Technique, rankName[r.rank], ref)
	}

	// MISS(None/Telemetry=未検知)は次スプリント候補として明示。
	fmt.Println("\n--- MISS 一覧 (未検知=None/Telemetry → 負債台帳へ) ---")
	miss := 0
	for _, r := range results {
		if r.rank < rankGeneral {
			fmt.Printf("  %-12s %-10s %s\n", r.run.Technique, rankName[r.rank], r.run.TestName)
			miss++
		}
	}
	if miss == 0 {
		fmt.Println("  (なし)")
	}
}

func writeScorecardCSV(path string, results []result) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	if err := w.Write([]string{"technique", "test_name", "rank", "rank_name", "latency_sec", "matched_by", "exit_code"}); err != nil {
		return err
	}
	for _, r := range results {
		lat := ""
		if r.latency >= 0 {
			lat = strconv.FormatFloat(r.latency.Seconds(), 'f', 1, 64)
		}
		if err := w.Write([]string{
			r.run.Technique, r.run.TestName, strconv.Itoa(r.rank), rankName[r.rank],
			lat, r.matchedBy, r.run.ExitCode,
		}); err != nil {
			return err
		}
	}
	return w.Error()
}

func pct(a, b int) string {
	if b == 0 {
		return "n/a"
	}
	return fmt.Sprintf("%5.1f%% (%d/%d)", 100*float64(a)/float64(b), a, b)
}

func median(d []time.Duration) time.Duration {
	if len(d) == 0 {
		return -1
	}
	sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
	m := len(d) / 2
	if len(d)%2 == 1 {
		return d[m]
	}
	return (d[m-1] + d[m]) / 2
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "エラー: "+format+"\n", a...)
	os.Exit(1)
}
