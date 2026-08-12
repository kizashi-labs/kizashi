package rules

import (
	"context"
	"testing"
)

// Guards the T1005 recursive sensitive-file-enumeration rule (migration 308).
// The detection block here MUST mirror 308's YAML. The rule fills the last
// Caldera "Find files" gap: PowerShell that recursively enumerates files by
// extension and projects full paths / caps results — tradecraft that process
// telemetry misses (Get-ChildItem is a cmdlet, not a spawned process), so it is
// matched on ScriptBlockText (PS4104) and, as a fallback, the command line.
const t1005EnumRule = `
title: Recursive Sensitive File Enumeration (Collection)
status: stable
level: medium
tags:
  - attack.t1005
  - attack.collection
logsource:
  product: windows
  category: ps_script
detection:
  enum_cmd:
    CommandLine|contains|all:
      - '-Recurse'
      - '-Include'
  out_cmd:
    CommandLine|contains:
      - '.FullName'
      - 'Select-Object -First'
  enum_script:
    ScriptBlockText|contains|all:
      - '-Recurse'
      - '-Include'
  out_script:
    ScriptBlockText|contains:
      - '.FullName'
      - 'Select-Object -First'
  condition: (enum_cmd and out_cmd) or (enum_script and out_script)
`

// The exact Caldera ability-90c2efaa command must fire via the script-block path.
// The engine flatten aliases script_block_text→ScriptBlockText upstream; here we
// set the resolved literal key, which sigma-go looks up directly (no field map).
func TestRuleEngine_Sigma_T1005_FindFiles_ScriptBlock(t *testing.T) {
	e := NewRuleEngine()
	e.LoadRules([]*DetectionRule{sigmaRule("t1005-enum", t1005EnumRule)})

	script := map[string]any{
		"type":            "script",
		"agent_id":        "host-1",
		"ScriptBlockText": `Get-ChildItem C:\Users -Recurse -Include *.yml -ErrorAction 'SilentlyContinue' | foreach {$_.FullName} | Select-Object -first 5;exit 0;`,
	}
	m, err := e.Evaluate(context.Background(), script)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !hasRule(m, "t1005-enum") {
		t.Fatalf("Caldera 'Find files' script (Get-ChildItem -Recurse -Include | %%{$_.FullName} | Select -first) should match T1005, got %d matches", len(m))
	}
}

// The same tradecraft arriving inline on the command line must also fire.
func TestRuleEngine_Sigma_T1005_FindFiles_CommandLine(t *testing.T) {
	e := NewRuleEngine()
	e.LoadRules([]*DetectionRule{sigmaRule("t1005-enum", t1005EnumRule)})

	proc := map[string]any{
		"type":        "process",
		"agent_id":    "host-1",
		"imagePath":   `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		"commandLine": `powershell -c "Get-ChildItem C:\Users -Recurse -Include *.docx | foreach {$_.FullName}"`,
	}
	if m, _ := e.Evaluate(context.Background(), proc); !hasRule(m, "t1005-enum") {
		t.Fatalf("inline command-line recursive file enumeration should match T1005")
	}
}

// A lone recursive listing (no -Include filter, no full-path/limit projection)
// is benign and must NOT match — this keeps the rule off ubiquitous admin usage.
func TestRuleEngine_Sigma_T1005_FindFiles_BenignNoMatch(t *testing.T) {
	e := NewRuleEngine()
	e.LoadRules([]*DetectionRule{sigmaRule("t1005-enum", t1005EnumRule)})

	benign := []map[string]any{
		{"type": "script", "agent_id": "h", "ScriptBlockText": `Get-ChildItem C:\logs -Recurse | Measure-Object`},
		{"type": "script", "agent_id": "h", "ScriptBlockText": `Get-ChildItem -Include *.tmp | Remove-Item`},
	}
	for i, ev := range benign {
		if m, _ := e.Evaluate(context.Background(), ev); hasRule(m, "t1005-enum") {
			t.Errorf("benign case %d should not match the T1005 enumeration rule", i)
		}
	}
}
