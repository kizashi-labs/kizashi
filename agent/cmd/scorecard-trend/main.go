// scorecard-trend は attack-scorer が出力したスコアカード CSV 群
// (docs/results/live-*.csv 等) を横断集計し、定点観測の経時トレンドを算出する。
//
// MITRE ATT&CK Evaluations 準拠のランク(None=0/Telemetry=1/General=2/Tactic=3/
// Technique=4)を attack-scorer と同基準で解釈し、実行(CSV)ごとに
// 可視性率(rank>=1)・検知率(rank>=3)・解析検知率(rank==4)・MTTD 中央値・見逃し数を出す。
//
// 使い方:
//
//	go run ./cmd/scorecard-trend docs/results/live-*.csv          # Markdown 表を stdout へ
//	go run ./cmd/scorecard-trend -format csv  docs/results/live-*.csv
//	go run ./cmd/scorecard-trend -format json docs/results/live-*.csv -out trend.json
//
// ファイル名 live-YYYYMMDD-… から日付を抽出して昇順に並べ、直近実行が前回比で
// 検知率を落としていれば stderr に回帰警告を出す(定点観測ゲート向け)。
// 回帰判定は「同じプラットフォームの前回実行」を相手に選び、さらに「両実行が
// 共通して計測した technique」に母集団を揃えて行う。ライブ計測は実行ごとに
// シナリオ・OS・技法数が違うため、直前の1件と全体率を比べるだけでは、難しい
// 技法を計測対象に加えただけで偽の回帰になり、Windows と Linux が交互に並べば
// OS 跨ぎの無意味な比較になる。プラットフォームはファイル名
// (live-YYYYMMDD-<platform>-<シナリオ>.csv)から推定する。
//
// 終了コード:
//
//	0  正常
//	1  有効なスコアカードが1件も無い / 出力の書き込み失敗
//	2  引数(CSVパス)が無い
//	3  検知率の回帰を検出(-fail-on-regress=false で抑止可)
//	4  読めないスコアカードがあった(-fail-on-parse-error=false で抑止可)
package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Summary は 1 スコアカード(= 1 実行)の集計結果。
type Summary struct {
	File          string  `json:"file"`
	Date          string  `json:"date"`
	Techniques    int     `json:"techniques"`
	VisibilityPct float64 `json:"visibility_pct"`
	DetectionPct  float64 `json:"detection_pct"`
	TechniquePct  float64 `json:"technique_pct"`
	MTTDMedianSec float64 `json:"mttd_median_sec"`
	Misses        int     `json:"misses"`
	// Platform はファイル名から推定した計測対象 OS("windows"/"linux"/"darwin"、
	// 判別できなければ空)。回帰判定で「同じプラットフォームの前回」を選ぶために使う。
	Platform string `json:"platform"`

	// ranks は technique -> その実行での最良ランク。実行間で母集団(計測した
	// technique 集合)が変わっても公平に比較できるよう、回帰判定でコホートを
	// 取るために保持する。出力形式(md/csv/json)には含めない。
	ranks map[string]int
}

var dateRe = regexp.MustCompile(`(\d{8})`)

func extractDate(path string) string {
	m := dateRe.FindString(filepath.Base(path))
	if len(m) == 8 {
		return m[:4] + "-" + m[4:6] + "-" + m[6:]
	}
	return ""
}

var platformRe = regexp.MustCompile(`(?i)(?:^|[-_])(windows|linux|darwin|macos)(?:[-_.]|$)`)

// extractPlatform はファイル名から計測対象 OS を推定する。
// live-YYYYMMDD-<platform>-<シナリオ>.csv という既存の命名規約に依存しており、
// 判別できなければ空を返す(空同士でのみ比較される)。
func extractPlatform(path string) string {
	m := platformRe.FindStringSubmatch(filepath.Base(path))
	if len(m) < 2 {
		return ""
	}
	p := strings.ToLower(m[1])
	if p == "macos" {
		return "darwin"
	}
	return p
}

// summarise は 1 CSV を読み、technique ごとの最良ランクから指標を計算する。
func summarise(path string) (*Summary, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.FieldsPerRecord = -1 // 末尾カンマ等の揺れを許容
	rows, err := r.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("%s: 空のCSV", path)
	}

	// ヘッダ列位置を解決(technique / rank / latency_sec)
	head := rows[0]
	col := map[string]int{}
	for i, h := range head {
		// Windows 系ツールが書いた CSV は先頭に UTF-8 BOM が残ることがある。
		// 剥がさないと最初の列名が一致せず「technique 列が無い」と誤判定し、
		// そのファイルが警告だけ出して集計から静かに落ちる(=ゲートが素通りする)。
		col[strings.TrimSpace(strings.ToLower(strings.TrimPrefix(h, "\ufeff")))] = i
	}
	ti, ok1 := col["technique"]
	ri, ok2 := col["rank"]
	if !ok1 || !ok2 {
		return nil, fmt.Errorf("%s: technique/rank 列が見つかりません", path)
	}
	li, hasLat := col["latency_sec"]

	bestRank := map[string]int{}
	latByTech := map[string]float64{} // 検知(rank>=3)した technique の代表 latency(最小=最速検知)
	for _, row := range rows[1:] {
		if len(row) <= ri || len(row) <= ti {
			continue
		}
		tech := strings.TrimSpace(row[ti])
		if tech == "" {
			continue
		}
		rank, err := strconv.Atoi(strings.TrimSpace(row[ri]))
		if err != nil {
			continue
		}
		if cur, ok := bestRank[tech]; !ok || rank > cur {
			bestRank[tech] = rank
		}
		if hasLat && rank >= 3 && li < len(row) {
			if v, err := strconv.ParseFloat(strings.TrimSpace(row[li]), 64); err == nil && v >= 0 {
				if cur, ok := latByTech[tech]; !ok || v < cur {
					latByTech[tech] = v
				}
			}
		}
	}

	total := len(bestRank)
	if total == 0 {
		return nil, fmt.Errorf("%s: 有効な technique 行がありません", path)
	}
	var visible, detected, technique, misses int
	for _, rk := range bestRank {
		if rk >= 1 {
			visible++
		}
		if rk >= 3 {
			detected++
		}
		if rk == 4 {
			technique++
		}
		if rk == 0 {
			misses++
		}
	}

	lats := make([]float64, 0, len(latByTech))
	for _, v := range latByTech {
		lats = append(lats, v)
	}
	sort.Float64s(lats)
	median := -1.0
	if n := len(lats); n > 0 {
		if n%2 == 1 {
			median = lats[n/2]
		} else {
			median = (lats[n/2-1] + lats[n/2]) / 2
		}
	}

	pct := func(n int) float64 { return float64(n) * 100 / float64(total) }
	return &Summary{
		File:          filepath.Base(path),
		Date:          extractDate(path),
		Techniques:    total,
		VisibilityPct: round1(pct(visible)),
		DetectionPct:  round1(pct(detected)),
		TechniquePct:  round1(pct(technique)),
		MTTDMedianSec: round1(median),
		Misses:        misses,
		Platform:      extractPlatform(path),
		ranks:         bestRank,
	}, nil
}

// commonTechniques は2実行が両方で計測した technique を昇順で返す。
func commonTechniques(a, b *Summary) []string {
	common := make([]string, 0, len(a.ranks))
	for t := range a.ranks {
		if _, ok := b.ranks[t]; ok {
			common = append(common, t)
		}
	}
	sort.Strings(common)
	return common
}

// cohortDetectionPct は techs に限定した検知率(rank>=3)を返す。
func cohortDetectionPct(s *Summary, techs []string) float64 {
	if len(techs) == 0 {
		return -1
	}
	var detected int
	for _, t := range techs {
		if s.ranks[t] >= 3 {
			detected++
		}
	}
	return round1(float64(detected) * 100 / float64(len(techs)))
}

// pickBaseline は last と比較すべき「同じプラットフォームの直前の実行」を返す。
// 単純に1つ前を取ると、Windows と Linux の計測が交互に並んだときに OS 跨ぎの
// 比較になり、共通 technique がほぼ無いのでゲートが毎回スキップされて実質
// 無効化される。プラットフォームが判別できない実行同士も同様に対応づける。
func pickBaseline(ss []*Summary, lastIdx int) *Summary {
	target := ss[lastIdx].Platform
	for i := lastIdx - 1; i >= 0; i-- {
		if ss[i].Platform == target {
			return ss[i]
		}
	}
	return nil
}

// platformLabel は判定文に出す表示名。
func platformLabel(p string) string {
	if p == "" {
		return "不明"
	}
	return p
}

// checkRegression は直近 vs「同じプラットフォームの前回」の検知率を、両実行が
// 共通して計測した technique だけに母集団を揃えて比較する。全体率の単純比較だと
// 「難しい技法を新たに計測対象へ加えた」「別シナリオを回した」だけで率が動き、
// 既存検知が何も壊れていないのに回帰と誤判定してしまう。共通コホートが
// minOverlap 未満なら比較する土台が無いとみなして判定しない。
// 戻り値は人間向けの判定文と、回帰とみなすかどうか。
func checkRegression(ss []*Summary, tol float64, minOverlap int) (string, bool) {
	if len(ss) < 2 {
		return "", false
	}
	last := ss[len(ss)-1]
	prev := pickBaseline(ss, len(ss)-1)
	if prev == nil {
		return fmt.Sprintf("回帰判定スキップ: %s と同じプラットフォーム(%s)の過去実行がありません。",
			last.File, platformLabel(last.Platform)), false
	}
	common := commonTechniques(prev, last)
	if len(common) < minOverlap {
		return fmt.Sprintf("回帰判定スキップ: %s と %s の共通 technique は %d 件のみ(必要 %d)。母集団が異なるため比較しません。",
			prev.File, last.File, len(common), minOverlap), false
	}
	prevPct := cohortDetectionPct(prev, common)
	lastPct := cohortDetectionPct(last, common)
	if drop := prevPct - lastPct; drop > tol {
		return fmt.Sprintf("回帰検出(%s): 共通 %d technique の検知率 %.1f%% → %.1f%%(%.1fpt 低下, 許容 %.1f)。前回=%s / 直近=%s",
			platformLabel(last.Platform), len(common), prevPct, lastPct, drop, tol, prev.File, last.File), true
	}
	return fmt.Sprintf("回帰なし(%s): 共通 %d technique の検知率 %.1f%% → %.1f%%(前回=%s / 直近=%s)",
		platformLabel(last.Platform), len(common), prevPct, lastPct, prev.File, last.File), false
}

func round1(f float64) float64 {
	if f < 0 {
		return f
	}
	return float64(int(f*10+0.5)) / 10
}

func main() {
	format := flag.String("format", "md", "出力形式: md | csv | json")
	out := flag.String("out", "", "出力先ファイル(未指定なら stdout)")
	regressTol := flag.Float64("regress-tol", 0, "直近実行が前回比で(共通technique上の)検知率をこのpt超下げたら exit 3")
	minOverlap := flag.Int("regress-min-overlap", 3, "回帰判定に必要な共通 technique 数。下回れば母集団が違うとみなし判定しない")
	failOnRegress := flag.Bool("fail-on-regress", true, "回帰検出時に exit 3 する。false なら判定結果を出すだけで正常終了(可視化専用の実行向け)")
	failOnParseError := flag.Bool("fail-on-parse-error", true, "読めないスコアカードCSVが1件でもあれば exit 4。false なら警告のみ(可視化専用の実行向け)")
	flag.Parse()

	paths := flag.Args()
	if len(paths) == 0 {
		fmt.Fprintln(os.Stderr, "使い方: scorecard-trend [-format md|csv|json] [-out file] <scorecard.csv ...>")
		os.Exit(2)
	}

	// 読めなかったファイルは黙って捨てない。1件でも落ちると、それが最新の実行
	// だった場合に「その前の2件」で回帰判定してしまい、最新の計測結果を一度も
	// 読んでいないのにゲートが緑になる。集計から欠けた事実を必ず表に出す。
	var summaries []*Summary
	var unreadable []string
	for _, p := range paths {
		s, err := summarise(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "警告: %v\n", err)
			unreadable = append(unreadable, filepath.Base(p))
			continue
		}
		summaries = append(summaries, s)
	}
	if len(summaries) == 0 {
		fmt.Fprintln(os.Stderr, "有効なスコアカードがありません")
		os.Exit(1)
	}

	// 日付昇順(日付なしは末尾)
	sort.SliceStable(summaries, func(i, j int) bool { return summaries[i].Date < summaries[j].Date })

	// 判定は出力前に済ませ、Markdown には注記として載せる(GITHUB_STEP_SUMMARY に
	// 出る形式なので、比較の前提が人間の目に見えるようにしておく)。
	verdict, regressed := checkRegression(summaries, *regressTol, *minOverlap)

	var notes []string
	if len(unreadable) > 0 {
		notes = append(notes, fmt.Sprintf("**読めなかったスコアカード %d/%d 件: %s** — この分は集計にも回帰判定にも入っていません。最新の実行が欠けている場合、判定は古い2実行の比較になります。",
			len(unreadable), len(paths), strings.Join(unreadable, ", ")))
	}
	if verdict != "" {
		notes = append(notes, verdict)
	}

	var body string
	switch *format {
	case "json":
		b, _ := json.MarshalIndent(summaries, "", "  ")
		body = string(b) + "\n"
	case "csv":
		body = renderCSV(summaries)
	default:
		body = renderMarkdown(summaries, notes)
	}

	if *out != "" {
		if err := os.WriteFile(*out, []byte(body), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "書き込み失敗: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "書き出し: %s (%d 実行)\n", *out, len(summaries))
	} else {
		fmt.Print(body)
	}

	if verdict != "" {
		fmt.Fprintln(os.Stderr, verdict)
	}
	// パースできなかったファイルの方を先に見る。判定の前提そのものが欠けている
	// 状態なので、回帰の有無より「判定が信用できない」ことを優先して報告する。
	if len(unreadable) > 0 {
		fmt.Fprintf(os.Stderr, "読めなかったスコアカード %d/%d 件: %s\n",
			len(unreadable), len(paths), strings.Join(unreadable, ", "))
		if *failOnParseError {
			os.Exit(4)
		}
	}
	if regressed && *failOnRegress {
		os.Exit(3)
	}
}

func renderMarkdown(ss []*Summary, notes []string) string {
	var b strings.Builder
	b.WriteString("# ATT&CK 検知率 定点観測トレンド\n\n")
	b.WriteString("attack-scorer スコアカードCSVから機械集計。ランクは MITRE Evals 準拠(検知=Tactic以上, 解析検知=Technique)。\n\n")
	b.WriteString("| 日付 | 実行 | 技数 | 可視性 | 検知(Tactic+) | 解析検知(Technique) | MTTD中央値 | 見逃し |\n")
	b.WriteString("|---|---|---:|---:|---:|---:|---:|---:|\n")
	for _, s := range ss {
		mttd := "—"
		if s.MTTDMedianSec >= 0 {
			mttd = fmt.Sprintf("%.1fs", s.MTTDMedianSec)
		}
		date := s.Date
		if date == "" {
			date = "—"
		}
		b.WriteString(fmt.Sprintf("| %s | %s | %d | %.0f%% | %.0f%% | %.0f%% | %s | %d |\n",
			date, s.File, s.Techniques, s.VisibilityPct, s.DetectionPct, s.TechniquePct, mttd, s.Misses))
	}
	// 表の各行は「その実行の母集団」での率であり、行間で母集団は揃っていない。
	// 回帰判定だけは共通 technique に揃えた別計算なので、その旨を注記で明示する。
	if len(notes) > 0 {
		b.WriteString("\n> 回帰判定は直近2実行が共通して計測した technique に母集団を揃えて行っています(表の率は各実行の母集団基準なので行間で直接比較できません)。\n")
		for _, n := range notes {
			b.WriteString(">\n> " + n + "\n")
		}
	}
	return b.String()
}

func renderCSV(ss []*Summary) string {
	var b strings.Builder
	b.WriteString("date,file,platform,techniques,visibility_pct,detection_pct,technique_pct,mttd_median_sec,misses\n")
	for _, s := range ss {
		b.WriteString(fmt.Sprintf("%s,%s,%s,%d,%.1f,%.1f,%.1f,%.1f,%d\n",
			s.Date, s.File, s.Platform, s.Techniques, s.VisibilityPct, s.DetectionPct, s.TechniquePct, s.MTTDMedianSec, s.Misses))
	}
	return b.String()
}
