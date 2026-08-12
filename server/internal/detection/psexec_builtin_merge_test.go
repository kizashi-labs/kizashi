package detection

import (
	"strings"
	"testing"
)

// builtinRuleYAML returns the builtin Sigma rule with the given title.
func builtinRuleYAML(t *testing.T, title string) string {
	t.Helper()
	for _, y := range builtinSigmaRules {
		if strings.Contains(y, "\ntitle: "+title+"\n") {
			return y
		}
	}
	t.Fatalf("builtin rule %q not found", title)
	return ""
}

func firesRule(t *testing.T, ruleYAML, title string, event map[string]interface{}) bool {
	t.Helper()
	ev := NewSigmaEvaluator()
	if err := ev.LoadRule(ruleYAML); err != nil {
		t.Fatalf("LoadRule(%s): %v", title, err)
	}
	addPipelineSigmaAliases(event)
	for _, m := range ev.EvaluateEvent(event) {
		if m.RuleTitle == title {
			return true
		}
	}
	return false
}

// TestBuiltinPsExecSubsumesDBRule is the precondition for migration 375, which
// disables the DB PsExec rule to stop one event raising two alerts (once from the
// API server's AlertPipeline, once from the detection engine). Disabling it is only
// safe if the builtin detects everything the DB rule did.
//
// migration 374 deliberately left this pair alone because neither was a subset of
// the other: only the DB rule matched psexec64.exe / paexec.exe / PSEXESVC, and only
// the builtin matched renamed binaries via Image|contains. The builtin has since
// absorbed the first three, so it should now fire on every event the DB rule fires
// on. This test asserts exactly that, event by event, rather than by reading the
// two YAMLs side by side.
func TestBuiltinPsExecSubsumesDBRule(t *testing.T) {
	builtin := builtinRuleYAML(t, "PsExec Remote Execution")

	cases := []struct {
		name  string
		event map[string]interface{}
	}{
		{"psexec.exe", map[string]interface{}{
			"type": "process", "image_path": `C:\Tools\psexec.exe`,
			"command_line": `psexec.exe \\HOST -u admin cmd`,
		}},
		{"psexec64.exe (DB-only before the merge)", map[string]interface{}{
			"type": "process", "image_path": `C:\Tools\psexec64.exe`,
			"command_line": `psexec64.exe \\HOST cmd`,
		}},
		// paexec is intentionally absent here: it is covered by a DIFFERENT builtin
		// ("PsExec-Alternative Remote Execution Tool"), asserted separately in
		// TestPaExecCoveredByAlternativeToolRule. Adding it to this rule too would
		// double-count it.
		{"psexesvc.exe", map[string]interface{}{
			"type": "process", "image_path": `C:\Windows\PSEXESVC.exe`,
			"command_line": `C:\Windows\PSEXESVC.exe`,
		}},
		{"-accepteula flag on a renamed binary", map[string]interface{}{
			"type": "process", "image_path": `C:\Temp\svchost_update.exe`,
			"command_line": `svchost_update.exe -accepteula \\HOST cmd`,
		}},
		{"PSEXESVC service artifact (DB-only before the merge)", map[string]interface{}{
			"type": "process", "image_path": `C:\Windows\System32\services.exe`,
			"command_line": `services.exe start PSEXESVC`,
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dbFires := firesRule(t, correctedPsExecRule, "PsExec Lateral Movement", cloneEvent(tc.event))
			builtinFires := firesRule(t, builtin, "PsExec Remote Execution", cloneEvent(tc.event))
			if dbFires && !builtinFires {
				t.Errorf("DB rule fires but builtin does not — disabling the DB rule (migration 375) "+
					"would lose this detection: %s", tc.name)
			}
			if !builtinFires {
				t.Errorf("builtin did not fire on genuine PsExec activity: %s", tc.name)
			}
		})
	}
}

// paexec.exe is the one thing the DB rule matched that this builtin deliberately
// does not: a separate builtin owns the PsExec clones. Migration 375 is only safe
// if that rule really covers it, so assert it rather than assume it — and assert
// that the merged rule stays out, since two builtins firing on one execution is
// the very duplication this work removes.
func TestPaExecCoveredByAlternativeToolRule(t *testing.T) {
	event := map[string]interface{}{
		"type": "process", "image_path": `C:\Tools\paexec.exe`,
		"command_line": `paexec.exe \\HOST cmd`,
	}
	if !firesRule(t, correctedPsExecRule, "PsExec Lateral Movement", cloneEvent(event)) {
		t.Fatal("precondition: the DB rule should match paexec.exe")
	}
	alt := builtinRuleYAML(t, "PsExec-Alternative Remote Execution Tool (PAExec/RemCom)")
	if !firesRule(t, alt, "PsExec-Alternative Remote Execution Tool (PAExec/RemCom)", cloneEvent(event)) {
		t.Error("paexec.exe is not covered by any builtin — migration 375 would lose this detection")
	}
	merged := builtinRuleYAML(t, "PsExec Remote Execution")
	if firesRule(t, merged, "PsExec Remote Execution", cloneEvent(event)) {
		t.Error("paexec.exe fires BOTH builtins — one execution would raise two alerts")
	}
}

// Widening the builtin must not resurrect the false positive migration 286 fixed:
// `curl -s ...` was once classified as PsExec lateral movement (observed live).
func TestBuiltinPsExecNoFalsePositive(t *testing.T) {
	builtin := builtinRuleYAML(t, "PsExec Remote Execution")

	benign := []struct {
		name  string
		event map[string]interface{}
	}{
		{"curl -s download", map[string]interface{}{
			"type": "process", "image_path": "/usr/bin/curl",
			"command_line": "curl -s -o /tmp/x https://example.invalid/generate_204",
		}},
		{"ss -s stats", map[string]interface{}{
			"type": "process", "image_path": "/usr/bin/ss", "command_line": "ss -s",
		}},
		{"windows dir /s", map[string]interface{}{
			"type": "process", "image_path": `C:\Windows\System32\cmd.exe`,
			"command_line": `cmd.exe /c dir /s C:\Users`,
		}},
		// The merge added "paexec" as a substring match; make sure an unrelated
		// binary that merely contains those letters in a path does not trip it.
		{"unrelated exec binary", map[string]interface{}{
			"type": "process", "image_path": `C:\Program Files\App\appexec.exe`,
			"command_line": `appexec.exe --run`,
		}},
	}
	for _, b := range benign {
		if firesRule(t, builtin, "PsExec Remote Execution", cloneEvent(b.event)) {
			t.Errorf("FALSE POSITIVE: %q fired the merged builtin PsExec rule", b.name)
		}
	}
}

// cloneEvent copies an event map so alias enrichment in one evaluation does not
// leak into the next.
func cloneEvent(in map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
