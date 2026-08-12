package main

import "testing"

func res(scenario, tech, name string, rank int) result {
	return result{run: runEntry{Scenario: scenario, Technique: tech, TestName: name}, rank: rank}
}

func resBlocked(scenario, tech, name string, rank int) result {
	r := res(scenario, tech, name, rank)
	r.blocked = true
	return r
}

// TestScoreChains verifies multi-stage chain scoring: per-scenario step counts on
// the visibility/detection/technique axes, the "chain broken" flag (≥1 step
// detected disrupts the attack), and that empty-scenario results are excluded.
func TestScoreChains(t *testing.T) {
	results := []result{
		// Scenario A: 3 steps — none / tactic / technique (time order preserved).
		res("intrusion-A", "T1566", "phish", rankNone),
		res("intrusion-A", "T1059", "powershell", rankTactic),
		resBlocked("intrusion-A", "T1003", "lsass-dump", rankTechnique), // detected AND prevented
		// Scenario B: 2 steps, both telemetry-only (visible, not detected).
		res("recon-B", "T1087", "whoami", rankTelemetry),
		res("recon-B", "T1082", "sysinfo", rankTelemetry),
		// No scenario — excluded from chain scoring.
		res("", "T1105", "download", rankTechnique),
	}

	chains := scoreChains(results)
	if len(chains) != 2 {
		t.Fatalf("expected 2 chains, got %d", len(chains))
	}

	a := chains[0]
	if a.Scenario != "intrusion-A" {
		t.Fatalf("first chain = %q, want intrusion-A (insertion order)", a.Scenario)
	}
	if a.Steps != 3 || a.Visible != 2 || a.Detected != 2 || a.Attributed != 1 || a.Protected != 1 {
		t.Errorf("A counts wrong: steps=%d visible=%d detected=%d attributed=%d protected=%d (want 3/2/2/1/1)",
			a.Steps, a.Visible, a.Detected, a.Attributed, a.Protected)
	}
	if !a.Broken {
		t.Error("A should be broken (a step was detected)")
	}
	if a.FirstHit != "powershell" {
		t.Errorf("A FirstHit = %q, want powershell (earliest detected step)", a.FirstHit)
	}

	b := chains[1]
	if b.Steps != 2 || b.Visible != 2 || b.Detected != 0 || b.Protected != 0 {
		t.Errorf("B counts wrong: steps=%d visible=%d detected=%d protected=%d (want 2/2/0/0)",
			b.Steps, b.Visible, b.Detected, b.Protected)
	}
	if b.Broken {
		t.Error("B should NOT be broken (no step detected, only telemetry)")
	}
}

// TestAlertIsBlocking verifies the Protection-axis marker detection across the
// real enforce-path alert wordings (eBPF deny, driver strip, generic block).
func TestAlertIsBlocking(t *testing.T) {
	blocking := []Alert{
		{Title: "実行前防御", Description: "実行を拒否（enforce, -EPERM）"},
		{Title: "[CRED] LSASSメモリ・アクセス", Description: "拒否（VM_READ剥奪・ダンプ阻止）"},
		{Title: "process blocked", Description: "execution prevented"},
	}
	for _, a := range blocking {
		if !a.isBlocking() {
			t.Errorf("alert should be blocking: %q / %q", a.Title, a.Description)
		}
	}
	notBlocking := []Alert{
		{Title: "[Sigma] Encoded PowerShell", Description: "Sigma rule matched"},
		{Title: "[MEMORY] 不審な実行メモリ領域", Description: "RWX unbacked region"},
	}
	for _, a := range notBlocking {
		if a.isBlocking() {
			t.Errorf("alert should NOT be blocking: %q / %q", a.Title, a.Description)
		}
	}
}
