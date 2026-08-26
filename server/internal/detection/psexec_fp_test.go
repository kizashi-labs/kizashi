package detection

import "testing"

// correctedPsExecRule mirrors the YAML in
// server/migrations/286_fix_psexec_lateral_movement_fp.sql. Keep them in sync:
// the migration is the source of truth for the live rule, this test guards its
// firing logic (no generic-flag false positives, real PsExec still detected).
const correctedPsExecRule = `title: PsExec Lateral Movement
id: a1b2c3d4-0001-0001-0001-000000000001
status: stable
description: Detects PsExec used for lateral movement.
logsource:
  category: process_creation
  product: windows
detection:
  selection_image:
    Image|endswith:
      - '\psexec.exe'
      - '\psexec64.exe'
      - '\paexec.exe'
      - '\psexesvc.exe'
  selection_artifact:
    CommandLine|contains:
      - '-accepteula'
      - 'PSEXESVC'
  condition: selection_image or selection_artifact
level: high
tags:
  - attack.t1021.002
  - attack.lateral_movement
`

// TestPsExecRuleNoFalsePositive verifies the corrected PsExec Lateral Movement
// rule no longer fires on benign commands that merely contain a ` -s ` / ` /s `
// flag (the original bug: `curl -s ...` was flagged as PsExec lateral movement,
// observed live in docs/results/live-20260701-linux-v2.md), while still
// detecting genuine PsExec activity.
func TestPsExecRuleNoFalsePositive(t *testing.T) {
	ev := NewSigmaEvaluator()
	if err := ev.LoadRule(correctedPsExecRule); err != nil {
		t.Fatalf("LoadRule: %v", err)
	}

	const title = "PsExec Lateral Movement"
	fires := func(event map[string]interface{}) bool {
		addPipelineSigmaAliases(event)
		for _, m := range ev.EvaluateEvent(event) {
			if m.RuleTitle == title {
				return true
			}
		}
		return false
	}

	// ── Must NOT fire: benign commands with generic -s / /s / backslashes ──
	benign := []struct {
		name  string
		event map[string]interface{}
	}{
		{"curl -s download", map[string]interface{}{
			"type":         "process",
			"image_path":   "/usr/bin/curl",
			"command_line": "curl -s -o /tmp/x https://www.google.com/generate_204",
		}},
		{"ss -s stats", map[string]interface{}{
			"type":         "process",
			"image_path":   "/usr/bin/ss",
			"command_line": "ss -s",
		}},
		{"ls /s path", map[string]interface{}{
			"type":         "process",
			"image_path":   "/usr/bin/ls",
			"command_line": "ls /some/path",
		}},
		{"windows dir /s", map[string]interface{}{
			"type":         "process",
			"image_path":   `C:\Windows\System32\cmd.exe`,
			"command_line": `cmd.exe /c dir /s C:\Users`,
		}},
	}
	for _, b := range benign {
		if fires(b.event) {
			t.Errorf("FALSE POSITIVE: %q fired PsExec rule", b.name)
		}
	}

	// ── Must fire: genuine PsExec activity ──
	truePos := []struct {
		name  string
		event map[string]interface{}
	}{
		{"psexec.exe image", map[string]interface{}{
			"type":         "process",
			"image_path":   `C:\Tools\PsExec.exe`,
			"command_line": `PsExec.exe \\host -u admin -p pass cmd`,
		}},
		{"psexec64 image", map[string]interface{}{
			"type":         "process",
			"image_path":   `C:\Sysinternals\psexec64.exe`,
			"command_line": `psexec64.exe \\10.0.0.5 cmd`,
		}},
		{"renamed binary, -accepteula artifact", map[string]interface{}{
			"type":         "process",
			"image_path":   `C:\Temp\svc.exe`,
			"command_line": `svc.exe -accepteula \\host cmd`,
		}},
		{"PSEXESVC service artifact", map[string]interface{}{
			"type":         "process",
			"image_path":   `C:\Windows\PSEXESVC.exe`,
			"command_line": `C:\Windows\PSEXESVC.exe`,
		}},
	}
	for _, p := range truePos {
		if !fires(p.event) {
			t.Errorf("MISSED true positive: %q did not fire PsExec rule", p.name)
		}
	}
}
