package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// AlertRow is one alert raised against a simulated host during a soak. Every
// row is a false positive by construction — the fleet only ever produced benign
// telemetry — which is what makes unattended labelling sound.
type AlertRow struct {
	ID        string
	RuleID    string
	Title     string
	Severity  int
	AgentID   string
	Technique string
	CreatedAt time.Time
}

// RuleStat is the per-rule verdict: how many false positives a rule produced,
// normalised to the unit commercial EDR is judged in.
type RuleStat struct {
	RuleID      string
	Title       string
	Alerts      int
	MaxSeverity int
	Techniques  []string
	Hosts       int      // distinct simulated hosts that tripped this rule
	Profiles    []string // which host classes tripped it
	Rate        float64  // false positives per 1000 hosts per day
	// Harness marks alerts produced by the measurement rig rather than by
	// detection content — see isHarnessArtifact.
	Harness bool
}

// Scorecard is a soak's result: the headline FP rate plus the per-rule breakdown
// that says which detection content to fix first.
type Scorecard struct {
	HostDays     float64
	TotalAlerts  int
	Rate         float64 // total false positives per 1000 hosts per day
	Rules        []RuleStat
	BySeverity   map[int]int
	ByProfile    map[string]int
	HostsAlerted int
	AgentCount   int

	// HarnessAlerts / DetectionAlerts split TotalAlerts by origin. TotalAlerts and
	// Rate stay whole — nothing is dropped, because a soak that quietly discards
	// some of its own alerts is a soak whose number cannot be trusted. But the two
	// halves answer different questions: DetectionRate is what detection content
	// costs an analyst, while the harness share is a fixed toll of the rig (one
	// offline + one health alert per simulated host when the run ends) that scales
	// with fleet size and would otherwise look like detection noise.
	HarnessAlerts   int
	DetectionAlerts int
	DetectionRate   float64
}

// isHarnessArtifact reports whether an alert came from the measurement rig rather
// than from detection content.
//
// fleet-sim's agents stop reporting the moment the soak ends, so heartbeat
// monitoring raises one "agent offline" and one "health warning" per simulated
// host every single run — 40 of the 445 alerts (9%) in the reference soak. They
// are real alerts about a real condition (the agent genuinely went away), so
// suppressing them would be wrong; they are simply not evidence about detection
// content, and counting them as such overstates rule noise by ~9% and makes the
// figure move with fleet size for reasons unrelated to detection.
//
// Matched on the alert titles heartbeat monitoring emits. Deliberately NOT matched
// on the fpsim- hostname prefix: in a soak every alert carries that prefix, so it
// would classify the whole run as harness noise.
func isHarnessArtifact(title string) bool {
	return strings.HasPrefix(title, "エージェントオフライン:") ||
		strings.HasSuffix(title, "ヘルス警告")
}

// unattributed labels alerts whose rule_id is NULL — typically the stateful
// runtime detectors (discovery / burst / fan-out / exfil-volume), which raise
// alerts directly rather than through a rules-table row. Grouping them under the
// alert title keeps them visible instead of collapsing them into one anonymous
// bucket, since those detectors are the most likely FP sources in this fleet.
const unattributed = "(no-rule-id)"

// Aggregate turns raw alert rows into a scorecard.
//
// hostDays is the simulated host-days the run covered, taken from the manifest.
// It is the denominator that makes runs of different size and speed comparable:
// 20 alerts from a 12-host 60-second run and 20 alerts from a 500-host overnight
// run are wildly different results, and only the normalised rate says so.
func Aggregate(rows []AlertRow, hostDays float64, agentProfile map[string]string, agentCount int) Scorecard {
	sc := Scorecard{
		HostDays:   hostDays,
		AgentCount: agentCount,
		BySeverity: map[int]int{},
		ByProfile:  map[string]int{},
	}

	type acc struct {
		stat       RuleStat
		hosts      map[string]bool
		profiles   map[string]bool
		techniques map[string]bool
	}
	byRule := map[string]*acc{}
	alertedHosts := map[string]bool{}

	for _, r := range rows {
		// A rule is identified by its title alone — deliberately not by rule_id.
		// rule_id is a per-database UUID minted when the migrations insert the
		// rule, so the same rule carries a different id in CI than it does on a
		// developer's machine, and a baseline keyed on it would report every DB
		// rule as brand new the first time it ran anywhere else. Titles survive
		// that trip, and they also keep the runtime detectors apart, which all
		// share an empty rule_id and would otherwise collapse into one row.
		key := ruleKey(RuleStat{Title: r.Title})

		a, ok := byRule[key]
		if !ok {
			a = &acc{
				stat:       RuleStat{RuleID: r.RuleID, Title: r.Title},
				hosts:      map[string]bool{},
				profiles:   map[string]bool{},
				techniques: map[string]bool{},
			}
			if a.stat.RuleID == "" {
				a.stat.RuleID = unattributed
			}
			byRule[key] = a
		}
		// Keep a real rule_id in the informational column when any row for this
		// title carries one; it is no longer part of the identity, but it is what
		// an operator greps for when they go looking for the rule in the DB.
		if a.stat.RuleID == unattributed && r.RuleID != "" {
			a.stat.RuleID = r.RuleID
		}
		a.stat.Alerts++
		if r.Severity > a.stat.MaxSeverity {
			a.stat.MaxSeverity = r.Severity
		}
		a.hosts[r.AgentID] = true
		if r.Technique != "" {
			a.techniques[r.Technique] = true
		}
		prof := agentProfile[r.AgentID]
		if prof == "" {
			prof = "(unknown)"
		}
		a.profiles[prof] = true

		sc.TotalAlerts++
		sc.BySeverity[r.Severity]++
		sc.ByProfile[prof]++
		alertedHosts[r.AgentID] = true
	}
	sc.HostsAlerted = len(alertedHosts)

	for _, a := range byRule {
		a.stat.Hosts = len(a.hosts)
		a.stat.Techniques = sortedKeys(a.techniques)
		a.stat.Profiles = sortedKeys(a.profiles)
		a.stat.Rate = perThousandHostDays(a.stat.Alerts, hostDays)
		a.stat.Harness = isHarnessArtifact(a.stat.Title)
		if a.stat.Harness {
			sc.HarnessAlerts += a.stat.Alerts
		}
		sc.Rules = append(sc.Rules, a.stat)
	}
	sc.DetectionAlerts = sc.TotalAlerts - sc.HarnessAlerts
	sc.DetectionRate = perThousandHostDays(sc.DetectionAlerts, hostDays)
	// Worst offender first; ties broken by title so output is stable and diffable.
	sort.Slice(sc.Rules, func(i, j int) bool {
		if sc.Rules[i].Alerts != sc.Rules[j].Alerts {
			return sc.Rules[i].Alerts > sc.Rules[j].Alerts
		}
		if sc.Rules[i].Title != sc.Rules[j].Title {
			return sc.Rules[i].Title < sc.Rules[j].Title
		}
		return sc.Rules[i].RuleID < sc.Rules[j].RuleID
	})

	sc.Rate = perThousandHostDays(sc.TotalAlerts, hostDays)
	return sc
}

// perThousandHostDays converts a raw count into false positives per 1000 hosts
// per day. A run with no simulated host-days yields 0 rather than an infinity
// that would poison every comparison downstream.
func perThousandHostDays(alerts int, hostDays float64) float64 {
	if hostDays <= 0 {
		return 0
	}
	return float64(alerts) / hostDays * 1000
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ─── CSV ──────────────────────────────────────────────────────

var csvHeader = []string{
	"rule_id", "title", "alerts", "max_severity", "hosts",
	"techniques", "profiles", "fp_per_1000_hosts_per_day",
}

// totalRow is the reserved rule_id for the whole-run line. It is written first
// so the headline number is readable without parsing the rest.
const totalRow = "TOTAL"

// WriteCSV serialises a scorecard. The TOTAL row carries the run's host-days in
// the techniques column so a baseline file records the scale it was measured at.
func WriteCSV(w io.Writer, sc Scorecard) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(csvHeader); err != nil {
		return err
	}
	total := []string{
		totalRow, "", strconv.Itoa(sc.TotalAlerts), "", strconv.Itoa(sc.HostsAlerted),
		fmt.Sprintf("host_days=%.4f", sc.HostDays), fmt.Sprintf("agents=%d", sc.AgentCount),
		formatRate(sc.Rate),
	}
	if err := cw.Write(total); err != nil {
		return err
	}
	for _, r := range sc.Rules {
		row := []string{
			r.RuleID, r.Title, strconv.Itoa(r.Alerts), strconv.Itoa(r.MaxSeverity),
			strconv.Itoa(r.Hosts), strings.Join(r.Techniques, "|"),
			strings.Join(r.Profiles, "|"), formatRate(r.Rate),
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

func formatRate(v float64) string {
	return strconv.FormatFloat(v, 'f', 2, 64)
}

// ReadCSV parses a scorecard written by WriteCSV, for baseline comparison.
func ReadCSV(r io.Reader) (Scorecard, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = len(csvHeader)
	records, err := cr.ReadAll()
	if err != nil {
		return Scorecard{}, fmt.Errorf("スコアカードCSVのパースに失敗しました: %w", err)
	}
	if len(records) == 0 {
		return Scorecard{}, fmt.Errorf("スコアカードCSVが空です")
	}

	sc := Scorecard{BySeverity: map[int]int{}, ByProfile: map[string]int{}}
	for i, rec := range records {
		if i == 0 {
			continue // header
		}
		if rec[0] == totalRow {
			sc.TotalAlerts = atoi(rec[2])
			sc.HostsAlerted = atoi(rec[4])
			sc.Rate = atof(rec[7])
			if hd, ok := strings.CutPrefix(rec[5], "host_days="); ok {
				sc.HostDays = atof(hd)
			}
			if ag, ok := strings.CutPrefix(rec[6], "agents="); ok {
				sc.AgentCount = atoi(ag)
			}
			continue
		}
		sc.Rules = append(sc.Rules, RuleStat{
			RuleID:      rec[0],
			Title:       rec[1],
			Alerts:      atoi(rec[2]),
			MaxSeverity: atoi(rec[3]),
			Hosts:       atoi(rec[4]),
			Techniques:  splitNonEmpty(rec[5]),
			Profiles:    splitNonEmpty(rec[6]),
			Rate:        atof(rec[7]),
		})
	}
	return sc, nil
}

func splitNonEmpty(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, "|")
}

func atoi(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

func atof(s string) float64 {
	f, _ := strconv.ParseFloat(strings.TrimSpace(s), 64)
	return f
}

// ─── regression gate ──────────────────────────────────────────

// Regression is one way the current run is worse than the baseline.
type Regression struct {
	Scope   string // "TOTAL" or a rule title
	Was     float64
	Now     float64
	Message string
}

// CompareBaseline reports how the current scorecard regressed against a
// baseline, in FP per 1000 hosts/day.
//
// Both the overall rate and each individual rule are checked. Checking only the
// total would let a newly noisy rule hide behind an unrelated improvement
// elsewhere — the exact shape of regression a curate round is most likely to
// introduce, since enabling a batch of SigmaHQ rules changes one category at a
// time.
//
// The two tolerances are deliberately separate, because the total and a single
// rule jitter by very different amounts. Measured across CI runs of the same
// seed, the total moved 351→356→369 alerts (18 alerts ≈ 10,800 at CI scale)
// while the individual rules behind it moved by at most one or two alerts —
// the total's spread is the sum of many small independent movements. A single
// tolerance therefore has to be either loose enough to be blind per-rule, or
// tight enough to be flaky overall. totalTol absorbs the aggregate jitter;
// ruleTol stays tight so a rule that genuinely turns noisy is still caught.
//
// newRuleFloor suppresses gate failures for rules whose absolute rate is below
// it, so a single stray alert on a tiny run does not turn into a red build.
func CompareBaseline(current, baseline Scorecard, totalTol, ruleTol, newRuleFloor float64) []Regression {
	var out []Regression

	// Both sides are quantised to the precision the CSV persists before any
	// comparison. A baseline is always read back from disk at 2 decimal places
	// while the current run carries full float64 precision, so re-scoring an
	// unchanged run yields e.g. 1999.9735… > 1999.97 and every rule is reported
	// as regressed at tolerance 0. Rounding both to the stored precision makes
	// "identical run" mean identical.
	current = quantise(current)
	baseline = quantise(baseline)

	if current.Rate > baseline.Rate+totalTol {
		out = append(out, Regression{
			Scope: totalRow, Was: baseline.Rate, Now: current.Rate,
			Message: fmt.Sprintf("全体の誤検知率が悪化しました: %.2f → %.2f (許容 +%.2f)",
				baseline.Rate, current.Rate, totalTol),
		})
	}

	baseByRule := map[string]RuleStat{}
	for _, r := range baseline.Rules {
		baseByRule[ruleKey(r)] = r
	}
	for _, r := range current.Rules {
		was := baseByRule[ruleKey(r)] // zero value when the rule is new
		if r.Rate <= was.Rate+ruleTol {
			continue
		}
		if r.Rate < newRuleFloor {
			continue
		}
		msg := fmt.Sprintf("ルール %q の誤検知率が悪化しました: %.2f → %.2f",
			r.Title, was.Rate, r.Rate)
		if was.Alerts == 0 {
			msg = fmt.Sprintf("新たに誤検知を出すルールです %q: %.2f /1000ホスト/日 (%d件)",
				r.Title, r.Rate, r.Alerts)
		}
		out = append(out, Regression{Scope: r.Title, Was: was.Rate, Now: r.Rate, Message: msg})
	}

	out = append(out, compareFamilies(current, baseline, ruleTol, newRuleFloor)...)

	sort.Slice(out, func(i, j int) bool {
		if out[i].Scope == totalRow {
			return true
		}
		if out[j].Scope == totalRow {
			return false
		}
		return out[i].Now > out[j].Now
	})
	return out
}

// ruleKey is the identity used both to aggregate a run and to line a run up
// against its baseline. It is the title only; see the comment in Aggregate for
// why rule_id must stay out of it.
//
// The leading [TAG] is case-folded, because that tag records WHICH PROCESS
// emitted the alert, not which rule fired. The api server writes "[Sigma] X" and
// the detection engine writes "[SIGMA] X" for the same rule — a distinction the
// dedup layer already had to learn to ignore (internal/dedup groups on
// lower(title) for exactly this reason).
//
// Without the fold, moving a rule between engines reads as two events the gate
// scores asymmetrically: the [SIGMA] row disappears (disappearances are not
// checked) and the [Sigma] row appears as a brand-new noisy rule. Migration 377
// did precisely that move and every affected rule's count went DOWN — 26→22,
// 20→8, 12→8 — yet the gate reported four new false-positive sources. It was
// keying on the emitting process.
//
// Folding also means a run that emits both spellings sums them into one row,
// which is the rule's true volume; scoring the halves separately would let a
// doubled rule pass twice at half its size.
func ruleKey(r RuleStat) string { return foldEnginePrefix(r.Title) }

// foldEnginePrefix lowercases a leading bracketed tag, leaving the rest of the
// title untouched. "[SIGMA] Foo" and "[Sigma] Foo" both become "[sigma] Foo";
// a title with no bracketed prefix is returned unchanged.
func foldEnginePrefix(title string) string {
	if !strings.HasPrefix(title, "[") {
		return title
	}
	end := strings.Index(title, "]")
	if end < 0 {
		return title
	}
	return strings.ToLower(title[:end+1]) + title[end+1:]
}

// quantise rounds every rate to the precision WriteCSV persists, so a scorecard
// compares equal to its own serialised form.
func quantise(sc Scorecard) Scorecard {
	out := sc
	out.Rate = roundRate(sc.Rate)
	out.Rules = make([]RuleStat, len(sc.Rules))
	copy(out.Rules, sc.Rules)
	for i := range out.Rules {
		out.Rules[i].Rate = roundRate(out.Rules[i].Rate)
	}
	return out
}

// roundRate mirrors formatRate's 2-decimal output.
func roundRate(v float64) float64 {
	rounded, err := strconv.ParseFloat(formatRate(v), 64)
	if err != nil {
		return v
	}
	return rounded
}

// ─── markdown ─────────────────────────────────────────────────

// WriteMarkdown renders the operator-facing summary.
func WriteMarkdown(w io.Writer, sc Scorecard, meta MarkdownMeta) error {
	b := &strings.Builder{}

	fmt.Fprintf(b, "# FPソーク スコアカード — %s\n\n", meta.RunLabel)
	fmt.Fprintf(b, "良性テレメトリのみで構成したフリートに対する実測。全アラートは定義上すべて誤検知。\n\n")

	fmt.Fprintf(b, "| 指標 | 値 |\n|---|---:|\n")
	fmt.Fprintf(b, "| シミュレートホスト数 | %d |\n", sc.AgentCount)
	fmt.Fprintf(b, "| シミュレートホスト日 | %.3f |\n", sc.HostDays)
	fmt.Fprintf(b, "| 送信イベント数 | %d |\n", meta.EventsTotal)
	fmt.Fprintf(b, "| **誤検知総数** | **%d** |\n", sc.TotalAlerts)
	fmt.Fprintf(b, "| **誤検知率 (件/1000ホスト/日)** | **%.1f** |\n", sc.Rate)
	fmt.Fprintf(b, "| 誤検知が出たホスト数 | %d / %d |\n", sc.HostsAlerted, sc.AgentCount)
	if sc.HarnessAlerts > 0 {
		fmt.Fprintf(b, "| ├ 検知コンテンツ由来 | %d (%.1f 件/1000ホスト/日) |\n",
			sc.DetectionAlerts, sc.DetectionRate)
		fmt.Fprintf(b, "| └ 測定ハーネス由来 | %d |\n", sc.HarnessAlerts)
	}
	fmt.Fprintf(b, "\n")
	if sc.HarnessAlerts > 0 {
		fmt.Fprintf(b, "> 総数は加工していない。内訳のうち**測定ハーネス由来**は、ソーク終了で\n"+
			"> fleet-sim のエージェントが一斉に応答を止めることによる死活監視アラート\n"+
			"> (ホストあたり「エージェントオフライン」+「ヘルス警告」の2件) で、検知ルールの\n"+
			"> 誤検知ではない。台数に比例するため、検知コンテンツの品質を論じるときは\n"+
			"> **検知コンテンツ由来**の行を引用すること。\n\n")
	}

	if len(sc.Rules) == 0 {
		fmt.Fprintf(b, "誤検知は検出されませんでした。\n")
		_, err := io.WriteString(w, b.String())
		return err
	}

	fmt.Fprintf(b, "## ルール別 誤検知 (多い順)\n\n")
	fmt.Fprintf(b, "| ルール | 件数 | 最大severity | 影響ホスト | プロファイル | 件/1000ホスト/日 |\n")
	fmt.Fprintf(b, "|---|---:|---:|---:|---|---:|\n")
	for _, r := range sc.Rules {
		title := escapePipes(r.Title)
		if r.Harness {
			title += " ⚙️" // measurement rig, not detection content
		}
		fmt.Fprintf(b, "| %s | %d | %d | %d | %s | %.1f |\n",
			title, r.Alerts, r.MaxSeverity, r.Hosts,
			escapePipes(strings.Join(r.Profiles, ", ")), r.Rate)
	}
	if sc.HarnessAlerts > 0 {
		fmt.Fprintf(b, "\n⚙️ = 測定ハーネス由来 (検知コンテンツの誤検知ではない)\n")
	}

	fmt.Fprintf(b, "\n## プロファイル別\n\n| プロファイル | 誤検知数 |\n|---|---:|\n")
	for _, name := range sortedCountKeys(sc.ByProfile) {
		fmt.Fprintf(b, "| %s | %d |\n", escapePipes(name), sc.ByProfile[name])
	}

	fmt.Fprintf(b, "\n## severity 分布\n\n| severity | 件数 |\n|---:|---:|\n")
	sevs := make([]int, 0, len(sc.BySeverity))
	for s := range sc.BySeverity {
		sevs = append(sevs, s)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(sevs)))
	for _, s := range sevs {
		fmt.Fprintf(b, "| %d | %d |\n", s, sc.BySeverity[s])
	}

	_, err := io.WriteString(w, b.String())
	return err
}

// MarkdownMeta carries run context that is not derivable from the alerts.
type MarkdownMeta struct {
	RunLabel    string
	EventsTotal int64
}

func escapePipes(s string) string { return strings.ReplaceAll(s, "|", `\|`) }

func sortedCountKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if m[keys[i]] != m[keys[j]] {
			return m[keys[i]] > m[keys[j]]
		}
		return keys[i] < keys[j]
	})
	return keys
}

// familyKeyRe strips an embedded subject from an alert title: the quoted process
// name in "プロセス 'rsync' が…", or a bare IP/host in the exfil detector's title.
var familyKeyRe = regexp.MustCompile(`'[^']*'|"[^"]*"|\b\d{1,3}(?:\.\d{1,3}){3}\b`)

// familyKey collapses titles that differ only in the subject they name.
//
// Some detectors put the offending process (or destination address) INTO the
// alert title, which is right for an analyst — "which process burst" is the
// first thing they need — but it splits one detector across many scorecard rows.
func familyKey(title string) string {
	return strings.TrimSpace(familyKeyRe.ReplaceAllString(foldEnginePrefix(title), "…"))
}

// compareFamilies catches a detector getting noisier when its output is spread
// across many per-subject titles.
//
// The per-title comparison above cannot see it. Measured on a benign 20-host
// soak, the file-burst heuristic produced 36 alerts under EIGHT titles — one per
// process (rsync, restic, robocopy.exe, MsMpEng.exe, go, find, …). Seven of the
// eight sat at 4 alerts, BELOW the 5-alert new-rule floor, so they were exempt
// from the gate entirely; and if the detector doubled, each title would grow by
// about 4, inside the per-rule tolerance. A 2× regression in a severity-8
// ransomware heuristic would have passed silently.
//
// Only families with more than one title are checked. A single-title family is
// already covered by the per-title pass, and reporting it twice would just make
// every ordinary regression print two lines.
//
// This does NOT second-guess the detectors that title themselves this way. The
// file-burst heuristic's noise on backup and build tooling is a deliberate,
// documented trade-off (see internal/detection/file_burst.go: the rate signal is
// the only observation surface for ransomware that skips shadow-copy deletion).
// The defect was never the noise — it was that the gate could not measure it.
func compareFamilies(current, baseline Scorecard, ruleTol, newRuleFloor float64) []Regression {
	agg := func(sc Scorecard) (rate map[string]float64, alerts map[string]int, titles map[string]int) {
		rate, alerts, titles = map[string]float64{}, map[string]int{}, map[string]int{}
		for _, r := range sc.Rules {
			k := familyKey(r.Title)
			rate[k] += r.Rate
			alerts[k] += r.Alerts
			titles[k]++
		}
		return
	}
	curRate, curAlerts, curTitles := agg(current)
	baseRate, _, _ := agg(baseline)

	keys := make([]string, 0, len(curRate))
	for k := range curRate {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var out []Regression
	for _, k := range keys {
		if curTitles[k] < 2 {
			continue // already covered per-title
		}
		now, was := roundRate(curRate[k]), roundRate(baseRate[k])

		// The tolerance has to grow with the family, or this check is flakier than
		// the thing it measures. ruleTol is calibrated for ONE rule's run-to-run
		// swing; a family is a sum of N of them, and the swing of a sum of roughly
		// independent counts grows as sqrt(N), not stays flat and not N. Using
		// ruleTol unscaled would fire on ordinary jitter across eight titles; using
		// ruleTol*N would be so loose that a doubling slips through (measured: 8
		// titles, 32→64 alerts is a delta of 19200, under a linear 24000 budget).
		tol := ruleTol * math.Sqrt(float64(curTitles[k]))
		if now <= was+tol || now < newRuleFloor {
			continue
		}
		msg := fmt.Sprintf("検知器 %q の誤検知率が悪化しました: %.2f → %.2f (許容 +%.2f / %d タイトルに分散, 計 %d件)",
			k, was, now, tol, curTitles[k], curAlerts[k])
		if was == 0 {
			msg = fmt.Sprintf("新たに誤検知を出す検知器です %q: %.2f /1000ホスト/日 (%d タイトルに分散, 計 %d件)",
				k, now, curTitles[k], curAlerts[k])
		}
		out = append(out, Regression{Scope: k, Was: was, Now: now, Message: msg})
	}
	return out
}
