package rules

import (
	"testing"
)

// stagedRule builds a behavioral DetectionRule with the given content for staged tests.
func stagedRule(id, content string) *DetectionRule {
	return &DetectionRule{
		ID:        id,
		Name:      "kill-chain " + id,
		Type:      "behavioral",
		Enabled:   true,
		Severity:  9,
		Content:   content,
		MITRETags: []string{"T1059"},
	}
}

const killChainContent = `
window: 10m
stages: 3
ordered: true
event_type: process
field: commandLine
stage_1: whoami, nltest, net group
stage_2: reg save, lsadump, ntdsutil
stage_3: psexec, winrs, wmic /node
`

// fire observes a process command line and reports whether the kill-chain rule fired.
func observeCmd(se *SequenceEngine, agent, cmd string) []*RuleMatch {
	return se.Observe(agent, "process", map[string]any{"commandLine": cmd})
}

func hasMatch(matches []*RuleMatch, id string) bool {
	for _, m := range matches {
		if m.RuleID == id {
			return true
		}
	}
	return false
}

func TestStagedKillChainOrdered_Fires(t *testing.T) {
	se := NewSequenceEngine()
	se.LoadRules([]*DetectionRule{stagedRule("kc", killChainContent)})

	// recon → credential access → lateral movement, in order.
	if m := observeCmd(se, "h1", `whoami /priv`); hasMatch(m, "kc") {
		t.Fatal("fired after stage 1 only")
	}
	if m := observeCmd(se, "h1", `reg save HKLM\SAM C:\sam.hive`); hasMatch(m, "kc") {
		t.Fatal("fired after stages 1-2 only")
	}
	if m := observeCmd(se, "h1", `psexec \\dc01 cmd`); !hasMatch(m, "kc") {
		t.Fatal("kill chain did not fire after all 3 stages in order")
	}
}

func TestStagedKillChainOrdered_WrongOrderNoFire(t *testing.T) {
	se := NewSequenceEngine()
	se.LoadRules([]*DetectionRule{stagedRule("kc", killChainContent)})

	// lateral first, then recon, then cred — stage_1 token appears only AFTER stage_3.
	observeCmd(se, "h1", `psexec \\dc01 cmd`)             // stage 3 token, but no stage 1 seen yet
	observeCmd(se, "h1", `reg save HKLM\SAM C:\sam.hive`) // stage 2
	m := observeCmd(se, "h1", `whoami /all`)              // stage 1 last
	if hasMatch(m, "kc") {
		t.Fatal("ordered kill chain fired on out-of-order stages")
	}
}

func TestStagedKillChain_PartialNoFire(t *testing.T) {
	se := NewSequenceEngine()
	se.LoadRules([]*DetectionRule{stagedRule("kc", killChainContent)})

	// Only stages 1 and 3 — stage 2 (credential access) never occurs.
	observeCmd(se, "h1", `nltest /dclist:corp`)
	if m := observeCmd(se, "h1", `winrs -r:dc01 cmd`); hasMatch(m, "kc") {
		t.Fatal("fired without the credential-access stage")
	}
}

func TestStagedKillChain_PerAgentIsolation(t *testing.T) {
	se := NewSequenceEngine()
	se.LoadRules([]*DetectionRule{stagedRule("kc", killChainContent)})

	// Stages split across two agents must NOT combine into one chain.
	observeCmd(se, "h1", `whoami`)
	observeCmd(se, "h2", `reg save HKLM\SAM x`)
	if m := observeCmd(se, "h1", `psexec \\dc cmd`); hasMatch(m, "kc") {
		t.Fatal("kill chain fired across two different agents")
	}
}

func TestStagedKillChainUnordered_Fires(t *testing.T) {
	se := NewSequenceEngine()
	content := `
window: 10m
stages: 2
event_type: process
field: commandLine
stage_1: lsadump, mimikatz
stage_2: psexec, winrs
`
	se.LoadRules([]*DetectionRule{stagedRule("u", content)})

	// Unordered: lateral observed before cred access still counts (both present in window).
	observeCmd(se, "h1", `winrs -r:host cmd`)
	if m := observeCmd(se, "h1", `mimikatz lsadump::sam`); !hasMatch(m, "u") {
		t.Fatal("unordered kill chain did not fire when both stages present")
	}
}

// shippedKillChainContent mirrors the rule body in migration
// 274_killchain_handson_intrusion.sql. Keep in sync — this test guards the actually
// shipped rule against typos that would make it silently never fire.
const shippedKillChainContent = `
window: 10m
stages: 3
ordered: true
event_type: process
field: commandLine
stage_1: whoami, nltest, net group, net localgroup, net view, dsquery, quser, klist, net accounts
stage_2: reg save, lsadump, sekurlsa, dcsync, ntdsutil, comsvcs, minidump, procdump, mimikatz, rubeus, vaultcmd
stage_3: psexec, psexesvc, winrs, wmic /node, /node:, invoke-command -computername, enter-pssession, new-pssession -computername, schtasks /s
group_by: agent_id
`

func TestShippedKillChainRuleFires(t *testing.T) {
	sr, err := parseSequenceRule(stagedRule("ship", shippedKillChainContent))
	if err != nil {
		t.Fatalf("shipped kill-chain rule failed to parse: %v", err)
	}
	if len(sr.stages) != 3 || !sr.ordered {
		t.Fatalf("shipped rule parsed as stages=%d ordered=%v, want 3/true", len(sr.stages), sr.ordered)
	}

	se := NewSequenceEngine()
	se.LoadRules([]*DetectionRule{stagedRule("ship", shippedKillChainContent)})
	observeCmd(se, "h1", `cmd.exe /c whoami /groups`)
	observeCmd(se, "h1", `procdump.exe -accepteula -ma lsass.exe out.dmp`)
	if m := observeCmd(se, "h1", `wmic /node:10.0.0.5 process call create "cmd /c calc"`); !hasMatch(m, "ship") {
		t.Fatal("shipped kill-chain rule did not fire on recon→creddump→lateral chain")
	}
}

// TestStagedRuleParsing verifies the staged shape is recognized and threshold defaults
// to the stage count.
func TestStagedRuleParsing(t *testing.T) {
	sr, err := parseSequenceRule(stagedRule("p", killChainContent))
	if err != nil {
		t.Fatalf("staged rule failed to parse: %v", err)
	}
	if len(sr.stages) != 3 {
		t.Errorf("got %d stages, want 3", len(sr.stages))
	}
	if !sr.ordered {
		t.Error("ordered flag not parsed")
	}
	if sr.threshold != 3 {
		t.Errorf("threshold defaulted to %d, want 3 (stage count)", sr.threshold)
	}
	if sr.field != "commandline" {
		t.Errorf("field = %q, want commandline", sr.field)
	}
}
