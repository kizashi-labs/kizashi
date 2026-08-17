package main

import (
	"os"
	"path/filepath"
	"testing"
)

// The committed baseline is produced by hand: the operator copies the scorecard
// CSV out of the FP soak job log and pastes it into docs/results. That is the
// documented procedure (see .github/workflows/fp-soak.yml), and it is exactly
// the kind of step a stray character survives.
//
// ReadCSV does reject a malformed baseline — but only inside the soak job, after
// the ~10 minute run and the 15 minute aggregation window have already elapsed.
// This test moves that failure to the front of CI, where it costs milliseconds.
//
// It deliberately checks self-consistency rather than specific numbers: the
// baseline is meant to change whenever the measurement legitimately changes, so
// pinning values here would only mean editing two files instead of one. What
// must never change is that the file parses and that its TOTAL row agrees with
// the rows above it — a TOTAL that disagrees would make the total-count guard
// and the per-rule guard disagree about the same run.
func TestCommittedBaselineIsWellFormed(t *testing.T) {
	path := filepath.Join("..", "..", "..", "docs", "results", "baseline_fp_soak.csv")

	f, err := os.Open(path) // #nosec G304 -- fixed repo-relative path, test-only
	if err != nil {
		t.Fatalf("ベースラインを開けませんでした: %v", err)
	}
	defer func() { _ = f.Close() }()

	sc, err := ReadCSV(f)
	if err != nil {
		t.Fatalf("ベースラインがパースできません（列数の食い違い、または貼り付け時の欠落）: %v", err)
	}

	if len(sc.Rules) == 0 {
		t.Fatal("ベースラインにルール行が 1 件もありません — ヘッダと TOTAL だけのファイルは比較対象にならず、ゲートが黙って無効になります")
	}

	sum := 0
	for _, r := range sc.Rules {
		if r.Title == "" {
			t.Errorf("タイトルが空の行があります (rule_id=%q) — 突合はタイトルで行うため、この行は照合されません", r.RuleID)
		}
		sum += r.Alerts
	}

	if sum != sc.TotalAlerts {
		t.Errorf("ルール行の合計 %d が TOTAL 行の %d と一致しません — どちらかが古い貼り付けです", sum, sc.TotalAlerts)
	}

	if sc.HostDays <= 0 || sc.AgentCount <= 0 {
		t.Errorf("TOTAL 行の host_days=%v / agents=%v が不正です — 正規化に使うため、0 だと率が意味を失います",
			sc.HostDays, sc.AgentCount)
	}
}
