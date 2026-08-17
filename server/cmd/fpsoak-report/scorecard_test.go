package main

import (
	"bytes"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func row(ruleID, title string, sev int, agent, tech string) AlertRow {
	return AlertRow{
		ID: "alert-" + title + agent, RuleID: ruleID, Title: title,
		Severity: sev, AgentID: agent, Technique: tech, CreatedAt: time.Unix(0, 0),
	}
}

func TestAggregateNormalisesToHostDays(t *testing.T) {
	rows := []AlertRow{
		row("r1", "Noisy Rule", 5, "a1", "T1059"),
		row("r1", "Noisy Rule", 7, "a2", "T1059"),
		row("r2", "Quiet Rule", 3, "a1", ""),
	}
	profiles := map[string]string{"a1": "it-admin", "a2": "office-pc"}

	sc := Aggregate(rows, 0.5, profiles, 12)

	if sc.TotalAlerts != 3 {
		t.Fatalf("total alerts = %d, want 3", sc.TotalAlerts)
	}
	// 3 alerts over half a host-day = 6 per host-day = 6000 per 1000 hosts/day.
	if math.Abs(sc.Rate-6000) > 0.01 {
		t.Errorf("rate = %.2f, want 6000", sc.Rate)
	}
	if len(sc.Rules) != 2 {
		t.Fatalf("rules = %d, want 2", len(sc.Rules))
	}
	// Worst offender first.
	if sc.Rules[0].Title != "Noisy Rule" {
		t.Errorf("rules not sorted by count: first = %q", sc.Rules[0].Title)
	}
	if sc.Rules[0].MaxSeverity != 7 {
		t.Errorf("max severity = %d, want 7", sc.Rules[0].MaxSeverity)
	}
	if sc.Rules[0].Hosts != 2 {
		t.Errorf("distinct hosts = %d, want 2", sc.Rules[0].Hosts)
	}
	if got := strings.Join(sc.Rules[0].Profiles, ","); got != "it-admin,office-pc" {
		t.Errorf("profiles = %q", got)
	}
	if sc.HostsAlerted != 2 {
		t.Errorf("hosts alerted = %d, want 2", sc.HostsAlerted)
	}
	if sc.ByProfile["it-admin"] != 2 {
		t.Errorf("by-profile it-admin = %d, want 2", sc.ByProfile["it-admin"])
	}
}

// TestAggregateKeepsRuntimeDetectorsSeparate guards a real collision: the
// stateful runtime detectors (discovery, file_burst, lateral_fanout,
// exfil_volume) all raise alerts with a NULL rule_id. Keying only on rule_id
// would merge them into one anonymous row, hiding which detector is noisy —
// and those detectors are the most likely FP sources in a benign fleet.
func TestAggregateKeepsRuntimeDetectorsSeparate(t *testing.T) {
	rows := []AlertRow{
		row("", "ホスト偵察バースト", 5, "a1", "T1082"),
		row("", "ホスト偵察バースト", 5, "a2", "T1082"),
		row("", "大量ファイル破壊操作", 9, "a3", "T1486"),
		row("", "横展開ファンアウト", 7, "a1", "T1021"),
	}
	sc := Aggregate(rows, 1, map[string]string{}, 3)

	if len(sc.Rules) != 3 {
		t.Fatalf("expected 3 distinct detectors, got %d: %+v", len(sc.Rules), sc.Rules)
	}
	for _, r := range sc.Rules {
		if r.RuleID != unattributed {
			t.Errorf("rule-less alert should be labelled %q, got %q", unattributed, r.RuleID)
		}
	}
	if sc.Rules[0].Title != "ホスト偵察バースト" || sc.Rules[0].Alerts != 2 {
		t.Errorf("top detector = %q (%d)", sc.Rules[0].Title, sc.Rules[0].Alerts)
	}
}

func TestAggregateHandlesZeroAlerts(t *testing.T) {
	sc := Aggregate(nil, 10, map[string]string{}, 5)
	if sc.TotalAlerts != 0 || sc.Rate != 0 || len(sc.Rules) != 0 {
		t.Errorf("empty run should score zero: %+v", sc)
	}
}

// TestAggregateZeroHostDaysDoesNotExplode: a division by zero would produce
// +Inf and poison every baseline comparison downstream.
func TestAggregateZeroHostDaysDoesNotExplode(t *testing.T) {
	sc := Aggregate([]AlertRow{row("r", "t", 5, "a", "")}, 0, map[string]string{}, 1)
	if math.IsInf(sc.Rate, 0) || math.IsNaN(sc.Rate) {
		t.Fatalf("rate = %v, want a finite value", sc.Rate)
	}
}

func TestAggregateIsStableAcrossRuns(t *testing.T) {
	rows := []AlertRow{
		row("r1", "A", 5, "a1", ""), row("r2", "B", 5, "a2", ""),
		row("r3", "C", 5, "a3", ""), row("r1", "A", 5, "a2", ""),
	}
	first := Aggregate(rows, 1, map[string]string{}, 3)
	for i := 0; i < 20; i++ {
		again := Aggregate(rows, 1, map[string]string{}, 3)
		for j := range first.Rules {
			if first.Rules[j].Title != again.Rules[j].Title {
				t.Fatalf("rule ordering is not stable at %d: %q vs %q",
					j, first.Rules[j].Title, again.Rules[j].Title)
			}
		}
	}
}

func TestCSVRoundTrip(t *testing.T) {
	rows := []AlertRow{
		row("r1", "Rule, with comma", 8, "a1", "T1059.001"),
		row("r1", "Rule, with comma", 6, "a2", "T1059"),
		row("", "Runtime | detector", 9, "a3", "T1486"),
	}
	sc := Aggregate(rows, 2.5, map[string]string{"a1": "it-admin", "a3": "backup-server"}, 20)

	var buf bytes.Buffer
	if err := WriteCSV(&buf, sc); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := ReadCSV(&buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	if got.TotalAlerts != sc.TotalAlerts {
		t.Errorf("total alerts %d != %d", got.TotalAlerts, sc.TotalAlerts)
	}
	if math.Abs(got.Rate-sc.Rate) > 0.01 {
		t.Errorf("rate %.4f != %.4f", got.Rate, sc.Rate)
	}
	if math.Abs(got.HostDays-sc.HostDays) > 0.0001 {
		t.Errorf("host days %.4f != %.4f — a baseline must record its own scale",
			got.HostDays, sc.HostDays)
	}
	if got.AgentCount != sc.AgentCount {
		t.Errorf("agent count %d != %d", got.AgentCount, sc.AgentCount)
	}
	if len(got.Rules) != len(sc.Rules) {
		t.Fatalf("rules %d != %d", len(got.Rules), len(sc.Rules))
	}
	for i := range sc.Rules {
		if got.Rules[i].Title != sc.Rules[i].Title {
			t.Errorf("rule %d title %q != %q", i, got.Rules[i].Title, sc.Rules[i].Title)
		}
		if got.Rules[i].Alerts != sc.Rules[i].Alerts {
			t.Errorf("rule %d alerts %d != %d", i, got.Rules[i].Alerts, sc.Rules[i].Alerts)
		}
		if strings.Join(got.Rules[i].Techniques, "|") != strings.Join(sc.Rules[i].Techniques, "|") {
			t.Errorf("rule %d techniques differ", i)
		}
	}
}

func TestReadCSVRejectsGarbage(t *testing.T) {
	if _, err := ReadCSV(strings.NewReader("")); err == nil {
		t.Error("empty input should be an error, not an empty passing scorecard")
	}
	if _, err := ReadCSV(strings.NewReader("a,b\n1,2\n")); err == nil {
		t.Error("wrong column count should be rejected")
	}
}

// ─── gate ─────────────────────────────────────────────────────

func scorecardOf(t *testing.T, hostDays float64, rows ...AlertRow) Scorecard {
	t.Helper()
	return Aggregate(rows, hostDays, map[string]string{}, 10)
}

func TestCompareBaselinePassesWhenImproved(t *testing.T) {
	baseline := scorecardOf(t, 1, row("r1", "A", 5, "a1", ""), row("r1", "A", 5, "a2", ""))
	current := scorecardOf(t, 1, row("r1", "A", 5, "a1", ""))

	if regs := CompareBaseline(current, baseline, 0, 0, 0); len(regs) != 0 {
		t.Errorf("an improvement must not fail the gate: %+v", regs)
	}
}

func TestCompareBaselineFlagsTotalRegression(t *testing.T) {
	baseline := scorecardOf(t, 1, row("r1", "A", 5, "a1", ""))
	current := scorecardOf(t, 1,
		row("r1", "A", 5, "a1", ""), row("r1", "A", 5, "a2", ""), row("r1", "A", 5, "a3", ""))

	regs := CompareBaseline(current, baseline, 0, 0, 0)
	if len(regs) == 0 {
		t.Fatal("expected the total-rate regression to be reported")
	}
	if regs[0].Scope != totalRow {
		t.Errorf("total regression should be reported first, got %q", regs[0].Scope)
	}
}

// TestCompareBaselineCatchesRuleHiddenByTotal is the reason per-rule comparison
// exists. A curate round can enable a noisy rule while an unrelated rule quiets
// down, leaving the overall rate flat or better. Gating on the total alone would
// wave that through — and a per-category curate round is precisely the change
// most likely to cause it.
func TestCompareBaselineCatchesRuleHiddenByTotal(t *testing.T) {
	baseline := scorecardOf(t, 1,
		row("r_old", "Old Noisy", 5, "a1", ""),
		row("r_old", "Old Noisy", 5, "a2", ""),
		row("r_old", "Old Noisy", 5, "a3", ""),
		row("r_old", "Old Noisy", 5, "a4", ""))
	current := scorecardOf(t, 1,
		row("r_old", "Old Noisy", 5, "a1", ""),
		row("r_new", "Newly Enabled", 5, "a2", ""),
		row("r_new", "Newly Enabled", 5, "a3", ""))

	if current.Rate > baseline.Rate {
		t.Fatalf("test setup is wrong: total should not have regressed (%.2f vs %.2f)",
			current.Rate, baseline.Rate)
	}
	regs := CompareBaseline(current, baseline, 0, 0, 0)
	if len(regs) == 0 {
		t.Fatal("a newly noisy rule must fail the gate even when the total improved")
	}
	found := false
	for _, r := range regs {
		if r.Scope == "Newly Enabled" {
			found = true
			if !strings.Contains(r.Message, "新たに") {
				t.Errorf("a brand-new offender should be reported as such: %s", r.Message)
			}
		}
	}
	if !found {
		t.Errorf("the new rule was not named in the regressions: %+v", regs)
	}
}

func TestCompareBaselineRespectsTolerance(t *testing.T) {
	baseline := scorecardOf(t, 1, row("r1", "A", 5, "a1", "")) // 1000 /1000hosts/day
	current := scorecardOf(t, 1, row("r1", "A", 5, "a1", ""),  // 2000
		row("r1", "A", 5, "a2", ""))

	if regs := CompareBaseline(current, baseline, 0, 0, 0); len(regs) == 0 {
		t.Error("without tolerance this must fail")
	}
	if regs := CompareBaseline(current, baseline, 1500, 1500, 0); len(regs) != 0 {
		t.Errorf("tolerance should absorb the jitter: %+v", regs)
	}
}

func TestCompareBaselineNewRuleFloorSuppressesNoise(t *testing.T) {
	baseline := scorecardOf(t, 100)                             // clean baseline
	current := scorecardOf(t, 100, row("r1", "A", 3, "a1", "")) // 10 /1000hosts/day

	if regs := CompareBaseline(current, baseline, 0, 0, 0); len(regs) == 0 {
		t.Error("without a floor, a single stray alert should be reported")
	}
	regs := CompareBaseline(current, baseline, 0, 0, 50)
	for _, r := range regs {
		if r.Scope != totalRow {
			t.Errorf("rules below the floor must not fail the gate: %+v", r)
		}
	}
}

func TestGateExitCodes(t *testing.T) {
	dir := t.TempDir()
	baselinePath := dir + "/baseline.csv"

	baseline := scorecardOf(t, 1, row("r1", "A", 5, "a1", ""))
	var buf bytes.Buffer
	if err := WriteCSV(&buf, baseline); err != nil {
		t.Fatal(err)
	}
	if err := writeFile(baselinePath, buf.Bytes()); err != nil {
		t.Fatal(err)
	}

	same := scorecardOf(t, 1, row("r1", "A", 5, "a1", ""))
	if code := gate(same, baselinePath, 0, 0, 0, 0); code != 0 {
		t.Errorf("unchanged run should exit 0, got %d", code)
	}

	worse := scorecardOf(t, 1, row("r1", "A", 5, "a1", ""), row("r1", "A", 5, "a2", ""))
	if code := gate(worse, baselinePath, 0, 0, 0, 0); code != exitRegression {
		t.Errorf("regressed run should exit %d, got %d", exitRegression, code)
	}

	// Budget alone, without a baseline.
	if code := gate(worse, "", 0, 0, 0, 100); code != exitRegression {
		t.Errorf("budget breach should exit %d, got %d", exitRegression, code)
	}
	if code := gate(worse, "", 0, 0, 0, 100000); code != 0 {
		t.Errorf("within budget should exit 0, got %d", code)
	}
}

// ─── markdown ─────────────────────────────────────────────────

func TestWriteMarkdownEscapesTablePipes(t *testing.T) {
	sc := Aggregate([]AlertRow{row("r1", "Rule | with pipe", 5, "a1", "")},
		1, map[string]string{"a1": "it-admin"}, 1)
	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, sc, MarkdownMeta{RunLabel: "test", EventsTotal: 100}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, `Rule \| with pipe`) {
		t.Errorf("unescaped pipe would break the table:\n%s", out)
	}
	if !strings.Contains(out, "誤検知率") {
		t.Errorf("headline metric missing:\n%s", out)
	}
}

func TestWriteMarkdownCleanRun(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, Aggregate(nil, 5, nil, 10),
		MarkdownMeta{RunLabel: "clean"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "誤検知は検出されませんでした") {
		t.Errorf("a clean run should say so explicitly:\n%s", buf.String())
	}
}

// ─── manifest ─────────────────────────────────────────────────

func TestLoadManifestRejectsUnscoreableRuns(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"zero host-days":  `{"schema_version":1,"simulated_host_days":0,"agent_count":5}`,
		"negative":        `{"schema_version":1,"simulated_host_days":-1}`,
		"inverted window": `{"schema_version":1,"simulated_host_days":1,"started_at":"2026-07-28T10:00:00Z","ended_at":"2026-07-28T09:00:00Z"}`,
		"not json":        `{`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			p := dir + "/" + strings.ReplaceAll(name, " ", "_") + ".json"
			if err := writeFile(p, []byte(body)); err != nil {
				t.Fatal(err)
			}
			if _, err := loadManifest(p); err == nil {
				t.Errorf("expected %s to be rejected", name)
			}
		})
	}
}

// TestScoringWindowIsDeterministic pins the property a baseline depends on: the
// window is a pure function of the manifest and the configured offset, never of
// when the tool happens to run. An earlier version ended the window "once alerts
// stopped arriving", which made the same run score 370 or 391 depending on the
// moment — no two runs were comparable.
func TestScoringWindowIsDeterministic(t *testing.T) {
	start := time.Date(2026, 7, 28, 10, 0, 0, 0, time.UTC)
	m := &Manifest{
		StartedAt: start, EndedAt: start.Add(10 * time.Minute), SimulatedHostDays: 1,
	}

	w := scoringWindow(m, 15*time.Minute)
	if !w.from.Before(start) {
		t.Error("window must start before the run to absorb clock skew")
	}
	// Stateful burst detectors fire only once their sliding window closes, so
	// alerts caused by the run keep landing after the last event was sent.
	if !w.to.Equal(m.EndedAt.Add(15 * time.Minute)) {
		t.Errorf("window end = %s, want run end + 15m", w.to)
	}
	for i := 0; i < 5; i++ {
		if again := scoringWindow(m, 15*time.Minute); !again.to.Equal(w.to) || !again.from.Equal(w.from) {
			t.Fatal("scoringWindow is not a pure function of its inputs")
		}
	}
}

func TestIndexAgentsSkipsUnenrolled(t *testing.T) {
	m := &Manifest{Agents: []ManifestAgent{
		{AgentID: "id1", Hostname: "h1", Profile: "office-pc"},
		{AgentID: "", Hostname: "h2", Profile: "dev-machine"}, // enrollment failed
	}}
	ids, profiles := indexAgents(m)
	if len(ids) != 1 || ids[0] != "id1" {
		t.Errorf("ids = %v, want [id1]", ids)
	}
	if profiles["id1"] != "office-pc" {
		t.Errorf("profile mapping lost: %v", profiles)
	}
}

func writeFile(path string, data []byte) error {
	return osWriteFile(path, data)
}

func osWriteFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}

// TestCompareBaselineAgainstOwnCSVIsClean is the regression guard for a gate
// that failed on an unchanged run. A baseline is always read back from CSV at
// 2 decimal places while the current run holds full float64 precision, so
// 1999.9735… compared against a stored 1999.97 reported every rule as regressed
// at tolerance 0 — the nightly gate would have gone red every single night with
// nothing actually wrong.
func TestCompareBaselineAgainstOwnCSVIsClean(t *testing.T) {
	// Rates that do not land on a 2-decimal boundary: 32 alerts / 2.0003 host-days.
	rows := make([]AlertRow, 0, 32)
	for i := 0; i < 32; i++ {
		rows = append(rows, row("r1", "A", 5, "a"+strconv.Itoa(i%7), ""))
	}
	current := Aggregate(rows, 2.0003, map[string]string{}, 20)

	var buf bytes.Buffer
	if err := WriteCSV(&buf, current); err != nil {
		t.Fatal(err)
	}
	baseline, err := ReadCSV(&buf)
	if err != nil {
		t.Fatal(err)
	}

	if regs := CompareBaseline(current, baseline, 0, 0, 0); len(regs) != 0 {
		t.Errorf("re-scoring an unchanged run must not report a regression, got %d:\n%+v",
			len(regs), regs)
	}
}

// TestResidualToleranceSeparatesBacklogFromTrickle pins the threshold that lets
// quiescence converge at all. The detection service runs periodic batch
// producers (correlation engine, retro rule hunter, insider-threat and
// network-anomaly schedulers) that emit a slow trickle indefinitely, so
// demanding an exactly flat count would fail every run at max-wait. The
// tolerance must absorb that trickle while still rejecting a backlog drain,
// which moves the count by the full ingest rate.
func TestResidualToleranceSeparatesBacklogFromTrickle(t *testing.T) {
	cases := []struct {
		count, growth int
		settled       bool
		what          string
	}{
		{300, 6, true, "background trickle on a 300-alert run"},
		{300, 40, false, "backlog still draining"},
		{20, 2, true, "single late alert on a small run"},
		{20, 9, false, "small run still climbing steeply"},
		{0, 0, true, "clean run with no alerts at all"},
	}
	for _, c := range cases {
		got := c.growth <= residualTolerance(c.count)
		if got != c.settled {
			t.Errorf("%s: growth=%d count=%d settled=%v, want %v (tolerance=%d)",
				c.what, c.growth, c.count, got, c.settled, residualTolerance(c.count))
		}
	}
}

// emit was refactored to close its output files explicitly (the deferred
// close used to swallow flush errors, which would leave a truncated scorecard
// that the next run's baseline comparison reads back as an improvement).
// This pins both halves: the happy path still writes both artefacts, and a
// path that cannot be created is reported rather than silently skipped.
func TestEmitWritesBothArtefactsAndReportsFailure(t *testing.T) {
	dir := t.TempDir()
	csv := filepath.Join(dir, "scorecard.csv")
	md := filepath.Join(dir, "scorecard.md")
	m := &Manifest{StartedAt: time.Unix(0, 0), EventsTotal: 42}

	if err := emit(Aggregate(nil, 5, nil, 10), m, csv, md); err != nil {
		t.Fatalf("emit: %v", err)
	}
	for _, p := range []string{csv, md} {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if len(b) == 0 {
			t.Errorf("%s は空です", p)
		}
	}

	missingDir := filepath.Join(dir, "does-not-exist", "scorecard.csv")
	if err := emit(Aggregate(nil, 5, nil, 10), m, missingDir, ""); err == nil {
		t.Error("作成できないパスに対して emit がエラーを返しませんでした")
	}
}

// The first CI run of the soak failed the gate because the committed baseline
// had been produced on a developer machine: rule_id is a per-database UUID
// minted by the migrations, so the same three Sigma rules carried different ids
// in CI and were reported as "newly producing false positives" even though
// their rates had gone *down*. Identity is the title, and only the title.
func TestBaselineMatchesAcrossDatabasesWithDifferentRuleIDs(t *testing.T) {
	const title = "[SIGMA] 疑わしいPowerShell実行"
	mk := func(ruleID string, n int) Scorecard {
		rows := make([]AlertRow, n)
		for i := range rows {
			rows[i] = row(ruleID, title, 7, "agent-"+strconv.Itoa(i), "T1059.001")
		}
		return Aggregate(rows, 1.6667, nil, 20)
	}

	// Same rule, same volume, two databases → no regression at zero tolerance.
	baseline := mk("91c42bbd-4345-495b-8826-12780fa65bc8", 31)
	current := mk("2f0b6d51-0000-4000-8000-ffffffffffff", 31)
	if got := CompareBaseline(current, baseline, 0, 0, 0); len(got) != 0 {
		t.Fatalf("rule_id が違うだけで退行と判定されました: %+v", got)
	}

	// And an actual improvement must not be reported as a new rule.
	if got := CompareBaseline(mk("another-id", 25), baseline, 0, 0, 0); len(got) != 0 {
		t.Errorf("件数が減ったのに退行と判定されました: %+v", got)
	}

	// A genuinely new title is still caught.
	newRule := Aggregate([]AlertRow{row("", "[BEHAVIORAL] 未知の検知", 8, "a", "T1000")},
		1.6667, nil, 20)
	if got := CompareBaseline(newRule, baseline, 0, 0, 0); len(got) != 1 {
		t.Errorf("新規ルールを検出できませんでした: %+v", got)
	}
}

// Runtime detectors all report a NULL rule_id; title keying must still keep them
// apart rather than collapsing them into one anonymous bucket.
func TestAggregateKeepsNullRuleIDDetectorsSeparate(t *testing.T) {
	sc := Aggregate([]AlertRow{
		row("", "[BEHAVIORAL] RDPブルートフォース検知", 8, "a", "T1110"),
		row("", "[HEURISTIC] ランサムウェアの疑い", 9, "b", "T1486"),
		row("", "[HEURISTIC] ランサムウェアの疑い", 9, "c", "T1486"),
	}, 1, nil, 3)
	if len(sc.Rules) != 2 {
		t.Fatalf("rule_id が NULL の検知器が %d 行に集約されました, want 2", len(sc.Rules))
	}
	for _, r := range sc.Rules {
		if r.RuleID != unattributed {
			t.Errorf("%q: RuleID=%q, want %q", r.Title, r.RuleID, unattributed)
		}
	}
}

// The total and a single rule jitter by different amounts: across CI runs of the
// same seed the total moved by 18 alerts while the rules behind it moved by one
// or two. A loose total tolerance must therefore not also loosen the per-rule
// check, or a rule that genuinely turns noisy slips through under the aggregate
// allowance.
func TestSeparateToleranceKeepsPerRuleCheckTight(t *testing.T) {
	baseline := Aggregate([]AlertRow{
		row("r1", "静かなルール", 5, "a", "T1"),
		row("r2", "うるさいルール", 5, "b", "T1"),
	}, 1, nil, 2)
	// 静かなルール unchanged; うるさいルール jumps 1 → 12 alerts.
	rows := []AlertRow{row("r1", "静かなルール", 5, "a", "T1")}
	for i := 0; i < 12; i++ {
		rows = append(rows, row("r2", "うるさいルール", 5, "b"+strconv.Itoa(i), "T1"))
	}
	current := Aggregate(rows, 1, nil, 2)

	// A single loose tolerance covering the aggregate move hides the rule.
	if regs := CompareBaseline(current, baseline, 12_000, 12_000, 0); len(regs) != 0 {
		t.Fatalf("前提が崩れています: 単一の緩い許容値でも退行が報告されました: %+v", regs)
	}
	// Splitting them catches it while still absorbing the total's jitter.
	regs := CompareBaseline(current, baseline, 12_000, 3_000, 0)
	if len(regs) != 1 {
		t.Fatalf("個別ルールの退行を検出できませんでした: %+v", regs)
	}
	if regs[0].Scope != "うるさいルール" {
		t.Errorf("Scope got %q, want %q", regs[0].Scope, "うるさいルール")
	}
}

// A rule that moves between the two detection processes keeps its identity.
//
// This is the 2026-08-05 failure, reduced. Migration 377 handed seven rules from
// server-detect to server-api; every one of them fired FEWER times afterwards,
// and the gate still reported four of them as new false-positive sources —
// because the alert title carries the emitting process as a [SIGMA]/[Sigma] tag
// and the baseline was keyed on it. A gate that a strict improvement cannot pass
// is not measuring what it claims to.
func TestBaselineLineupIgnoresEnginePrefixCase(t *testing.T) {
	baseline := Scorecard{
		Rate: 15599.95,
		Rules: []RuleStat{
			{Title: "[SIGMA] 疑わしいPowerShell実行", Alerts: 26, Rate: 15599.95},
		},
	}
	current := Scorecard{
		Rate: 13199.93,
		Rules: []RuleStat{
			// Same rule, now emitted by the api server: fewer alerts, different tag case.
			{Title: "[Sigma] 疑わしいPowerShell実行", Alerts: 22, Rate: 13199.93},
		},
	}

	if got := CompareBaseline(current, baseline, 42000, 3000, 3000); len(got) != 0 {
		t.Errorf("a rule that moved engines and got QUIETER was reported as a regression: %+v\n"+
			"  The [SIGMA]/[Sigma] tag names the process that emitted the alert, not the rule. "+
			"Keying the baseline on it makes an engine move look like an old rule vanishing "+
			"and a new noisy one appearing.", got)
	}

	// The fold must not blind the gate: the same rule genuinely getting noisier
	// still has to fail, tag case notwithstanding.
	louder := Scorecard{
		Rate: 40000,
		Rules: []RuleStat{
			{Title: "[Sigma] 疑わしいPowerShell実行", Alerts: 70, Rate: 40000},
		},
	}
	if got := CompareBaseline(louder, baseline, 42000, 3000, 3000); len(got) == 0 {
		t.Error("a rule that moved engines and got much NOISIER passed the gate — " +
			"the prefix fold has turned into a blind spot")
	}
}

// Both spellings in one run are one rule, summed — not two rules at half size.
func TestAggregateSumsBothEngineSpellings(t *testing.T) {
	sc := Aggregate([]AlertRow{
		{Title: "[SIGMA] Dup", AgentID: "a", Severity: 5},
		{Title: "[Sigma] Dup", AgentID: "a", Severity: 5},
	}, 1, map[string]string{}, 1)

	if len(sc.Rules) != 1 {
		var got []string
		for _, r := range sc.Rules {
			got = append(got, r.Title)
		}
		t.Fatalf("expected the two spellings to aggregate as one rule, got %d: %v\n"+
			"  Scoring the halves separately lets a double-counted rule pass twice at "+
			"half its measured volume.", len(sc.Rules), got)
	}
	if sc.Rules[0].Alerts != 2 {
		t.Errorf("alerts = %d, want 2 (both spellings summed)", sc.Rules[0].Alerts)
	}
}

// A detector that names its subject in the title must still be measurable.
//
// Built from the real shape observed on a benign 20-host soak: the file-burst
// heuristic produced 36 alerts under EIGHT titles (one per process), seven of
// them at 4 alerts — below the 5-alert new-rule floor, hence exempt from the
// gate. Doubling the detector leaves each title around 8, an increase of ~4,
// inside the per-rule tolerance of 5. Per-title, nothing fires.
func TestFamilyRollupCatchesSubjectTitledDetector(t *testing.T) {
	rules := func(per int, procs ...string) []RuleStat {
		var out []RuleStat
		for _, p := range procs {
			out = append(out, RuleStat{
				Title:  "[HEURISTIC] ランサムウェアの疑い: プロセス '" + p + "' が30秒内に多数のファイルを破壊的操作",
				Alerts: per,
				Rate:   float64(per) * 600,
			})
		}
		return out
	}
	procs := []string{"rsync", "restic", "robocopy.exe", "MsMpEng.exe", "go", "find", "node", "tar"}

	baseline := Scorecard{Rate: 100, Rules: rules(4, procs...)}
	doubled := Scorecard{Rate: 100, Rules: rules(8, procs...)}

	// Per-title alone is blind: +4 alerts each is inside ruleTol.
	var perTitle int
	for _, r := range doubled.Rules {
		was := 4 * 600.0
		if r.Rate > was+3000 {
			perTitle++
		}
	}
	if perTitle != 0 {
		t.Fatalf("premise broken: %d titles exceed the per-rule tolerance on their own, so this "+
			"test is no longer exercising the blind spot it was written for", perTitle)
	}

	regs := CompareBaseline(doubled, baseline, 42000, 3000, 3000)
	if len(regs) == 0 {
		t.Error("a detector that doubled (4→8 alerts across 8 per-process titles, 32→64 total) " +
			"passed the gate. Splitting one detector across many subject-titled rows hides it " +
			"from every per-title check: each row stays under the new-rule floor and each " +
			"increase stays inside the per-rule tolerance.")
	}

	// And it must not fire when nothing changed.
	if regs := CompareBaseline(baseline, baseline, 42000, 3000, 3000); len(regs) != 0 {
		t.Errorf("an unchanged run reported family regressions: %+v", regs)
	}
}

// The rollup must not collapse genuinely different rules into one bucket.
func TestFamilyRollupKeepsDistinctRulesApart(t *testing.T) {
	if a, b := familyKey("[Sigma] Domain Group Discovery"), familyKey("[Sigma] Domain Account Discovery"); a == b {
		t.Errorf("two unrelated rules share a family key %q — the subject stripper is too greedy", a)
	}
	// Same detector, different subject → same family.
	a := familyKey("[HEURISTIC] 疑い: プロセス 'rsync' が…")
	b := familyKey("[HEURISTIC] 疑い: プロセス 'restic' が…")
	if a != b {
		t.Errorf("same detector, different process, got different families: %q vs %q", a, b)
	}
	// Engine-prefix case still folds (the #647 fix must survive the rollup).
	if familyKey("[SIGMA] X") != familyKey("[Sigma] X") {
		t.Error("familyKey stopped folding the engine prefix")
	}
}
