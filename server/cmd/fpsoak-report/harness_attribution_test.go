package main

import (
	"strings"
	"testing"
	"time"
)

// The titles heartbeat monitoring actually emitted in the reference soak
// (docs/results/baseline_fp_soak.csv) — 20 offline + 20 health warnings out of
// 445 alerts. Classification is asserted against those exact strings so a
// rewording of either alert shows up here rather than silently reclassifying 9%
// of the run.
func TestIsHarnessArtifact(t *testing.T) {
	harness := []string{
		"エージェントオフライン: fpsim-wks-0010",
		"エージェントオフライン: fpsim-adm-0008",
		"エージェント fpsim-bkp-0000 ヘルス警告",
		"エージェント fpsim-dev-0002 ヘルス警告",
	}
	for _, title := range harness {
		if !isHarnessArtifact(title) {
			t.Errorf("harness alert not classified: %q", title)
		}
	}

	// Detection content — including alerts that merely mention an agent or a
	// simulated hostname — must never be reclassified as rig noise.
	detection := []string{
		"[SIGMA] 疑わしいPowerShell実行",
		"[HEURISTIC] ランサムウェアの疑い: プロセス 'go' が30秒内に多数のファイルを破壊的操作",
		"[BEHAVIORAL] RDPブルートフォース検知",
		"通常見られないプロセスが不審な場所から実行: MsMpEng.exe",
		"[KILLCHAIN] 多段攻撃の疑い: 複数段のATT&CK戦術を観測",
		"エージェント改ざんの疑い", // agent-related wording, but a real detection
	}
	for _, title := range detection {
		if isHarnessArtifact(title) {
			t.Errorf("detection alert misclassified as harness noise: %q", title)
		}
	}
}

func harnessRows() []AlertRow {
	now := time.Now()
	var rows []AlertRow
	// 3 hosts × (1 offline + 1 health) = 6 harness alerts
	for _, h := range []string{"fpsim-wks-0001", "fpsim-wks-0002", "fpsim-dev-0003"} {
		rows = append(rows,
			AlertRow{ID: "o-" + h, Title: "エージェントオフライン: " + h, Severity: 7, AgentID: h, CreatedAt: now},
			AlertRow{ID: "h-" + h, Title: "エージェント " + h + " ヘルス警告", Severity: 5, AgentID: h, CreatedAt: now},
		)
	}
	// 4 detection alerts across 2 rules
	rows = append(rows,
		AlertRow{ID: "d1", RuleID: "r-1", Title: "[SIGMA] 疑わしいPowerShell実行", Severity: 7, AgentID: "fpsim-wks-0001", CreatedAt: now},
		AlertRow{ID: "d2", RuleID: "r-1", Title: "[SIGMA] 疑わしいPowerShell実行", Severity: 7, AgentID: "fpsim-wks-0002", CreatedAt: now},
		AlertRow{ID: "d3", Title: "[BEHAVIORAL] RDPブルートフォース検知", Severity: 8, AgentID: "fpsim-dev-0003", CreatedAt: now},
		AlertRow{ID: "d4", Title: "[BEHAVIORAL] RDPブルートフォース検知", Severity: 8, AgentID: "fpsim-dev-0003", CreatedAt: now},
	)
	return rows
}

// The split must be additive: nothing is dropped from the headline figure. A soak
// that quietly discards some of its own alerts is a soak whose number cannot be
// trusted, so the total stays whole and only gains an explained breakdown.
func TestAggregateSplitsHarnessWithoutDroppingAnything(t *testing.T) {
	sc := Aggregate(harnessRows(), 1.0, map[string]string{}, 3)

	if sc.TotalAlerts != 10 {
		t.Fatalf("TotalAlerts = %d, want 10 (nothing may be dropped)", sc.TotalAlerts)
	}
	if sc.HarnessAlerts != 6 {
		t.Errorf("HarnessAlerts = %d, want 6", sc.HarnessAlerts)
	}
	if sc.DetectionAlerts != 4 {
		t.Errorf("DetectionAlerts = %d, want 4", sc.DetectionAlerts)
	}
	if sc.HarnessAlerts+sc.DetectionAlerts != sc.TotalAlerts {
		t.Errorf("split does not add up: %d + %d != %d",
			sc.HarnessAlerts, sc.DetectionAlerts, sc.TotalAlerts)
	}
	// 1.0 host-day → rate == count × 1000
	if sc.Rate != 10000 {
		t.Errorf("Rate = %.1f, want 10000 (the headline figure must stay whole)", sc.Rate)
	}
	if sc.DetectionRate != 4000 {
		t.Errorf("DetectionRate = %.1f, want 4000", sc.DetectionRate)
	}
}

func TestRuleStatCarriesHarnessFlag(t *testing.T) {
	sc := Aggregate(harnessRows(), 1.0, map[string]string{}, 3)
	for _, r := range sc.Rules {
		want := isHarnessArtifact(r.Title)
		if r.Harness != want {
			t.Errorf("rule %q: Harness = %v, want %v", r.Title, r.Harness, want)
		}
	}
}

// A run with no harness alerts must render exactly as before — the breakdown and
// its explanatory note appear only when there is something to explain.
func TestMarkdownOmitsBreakdownWhenNoHarnessAlerts(t *testing.T) {
	rows := []AlertRow{
		{ID: "d1", RuleID: "r-1", Title: "[SIGMA] 疑わしいPowerShell実行", Severity: 7, AgentID: "h1", CreatedAt: time.Now()},
	}
	sc := Aggregate(rows, 1.0, map[string]string{}, 1)
	var b strings.Builder
	if err := WriteMarkdown(&b, sc, MarkdownMeta{RunLabel: "test", EventsTotal: 1}); err != nil {
		t.Fatalf("WriteMarkdown: %v", err)
	}
	if strings.Contains(b.String(), "測定ハーネス由来") {
		t.Error("breakdown rendered even though the run had no harness alerts")
	}
}

func TestMarkdownShowsBreakdownAndMarksHarnessRows(t *testing.T) {
	sc := Aggregate(harnessRows(), 1.0, map[string]string{}, 3)
	var b strings.Builder
	if err := WriteMarkdown(&b, sc, MarkdownMeta{RunLabel: "test", EventsTotal: 100}); err != nil {
		t.Fatalf("WriteMarkdown: %v", err)
	}
	out := b.String()
	for _, want := range []string{"検知コンテンツ由来", "測定ハーネス由来", "⚙️"} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown missing %q", want)
		}
	}
	// The headline total must still be the unadjusted one.
	if !strings.Contains(out, "**10**") {
		t.Error("markdown no longer reports the unadjusted total")
	}
}
