package rules

import "testing"

// crossTypeKillChainContent uses stage_N_event_type/stage_N_field overrides so
// each stage reads a DIFFERENT event type's field — the gap the P2-follow-up
// (behavioral-engine deepening) closes: a rule-wide event_type/field cannot
// express "discovery process → WMI persistence → lateral named pipe →
// process-injection thread", because each of those event types populates a
// different field (commandline / wmi_consumer_type / pipe_name / target_image).
const crossTypeKillChainContent = `
window: 10m
stages: 2
ordered: true
stage_1_event_type: wmi_activity
stage_1_field: wmi_consumer_type
stage_1: commandlineeventconsumer, activescripteventconsumer
stage_2_event_type: named_pipe
stage_2_field: pipe_name
stage_2: psexesvc, remcom_
`

func TestStagedKillChain_CrossEventType_Fires(t *testing.T) {
	se := NewSequenceEngine()
	se.LoadRules([]*DetectionRule{stagedRule("xt", crossTypeKillChainContent)})

	// Stage 1: a WMI permanent-consumer persistence event.
	m := se.Observe("h1", "wmi_activity", map[string]any{"wmi_consumer_type": "CommandLineEventConsumer"})
	if hasMatch(m, "xt") {
		t.Fatal("fired after stage 1 only")
	}
	// Stage 2: a lateral-movement named pipe, on a DIFFERENT event type/field.
	m = se.Observe("h1", "named_pipe", map[string]any{"pipe_name": `\PSEXESVC`})
	if !hasMatch(m, "xt") {
		t.Fatal("cross-event-type kill chain did not fire (wmi_activity -> named_pipe)")
	}
}

// A stage_1-matching value on the WRONG event type must not satisfy the stage —
// the per-stage event_type filter must actually gate, not just the field name.
func TestStagedKillChain_CrossEventType_WrongEventTypeNoMatch(t *testing.T) {
	se := NewSequenceEngine()
	se.LoadRules([]*DetectionRule{stagedRule("xt", crossTypeKillChainContent)})

	// Same field name/value, but on event_type=process (not wmi_activity) — must
	// not satisfy stage 1.
	se.Observe("h1", "process", map[string]any{"wmi_consumer_type": "CommandLineEventConsumer"})
	m := se.Observe("h1", "named_pipe", map[string]any{"pipe_name": `\PSEXESVC`})
	if hasMatch(m, "xt") {
		t.Fatal("stage 1 matched on the wrong event_type — per-stage event_type filter not enforced")
	}
}

// A rule with NO per-stage overrides must behave exactly as before (regression
// guard for the stage_N_event_type/field addition).
func TestStagedKillChain_NoOverrides_Unaffected(t *testing.T) {
	se := NewSequenceEngine()
	se.LoadRules([]*DetectionRule{stagedRule("kc", killChainContent)})
	observeCmd(se, "h1", `whoami /priv`)
	observeCmd(se, "h1", `reg save HKLM\SAM C:\sam.hive`)
	if m := observeCmd(se, "h1", `psexec \\dc01 cmd`); !hasMatch(m, "kc") {
		t.Fatal("rule-wide event_type/field regressed after adding per-stage overrides")
	}
}

// shippedWMILateralKillChainContent mirrors the rule body in migration
// 318_killchain_wmi_persistence_lateral.sql. Keep in sync — this test guards
// the actually shipped cross-event-type rule against typos/regressions that
// would make it silently never fire (the same guard shippedKillChainContent
// gives migration 274).
const shippedWMILateralKillChainContent = `
window: 30m
stages: 2
ordered: false
stage_1_event_type: wmi_activity
stage_1_field: wmi_consumer_type
stage_1: commandlineeventconsumer, activescripteventconsumer
stage_2_event_type: named_pipe
stage_2_field: pipe_name
stage_2: psexesvc, psexecsvc, remcom_, paexec, csexecsvc, postex_, msagent_, dsernamepipe, wkssvc_
group_by: agent_id
`

func TestShippedWMILateralKillChainRule_Fires(t *testing.T) {
	sr, err := parseSequenceRule(stagedRule("wmilat", shippedWMILateralKillChainContent))
	if err != nil {
		t.Fatalf("shipped WMI+lateral kill-chain rule failed to parse: %v", err)
	}
	if len(sr.stages) != 2 || sr.ordered {
		t.Fatalf("shipped rule parsed as stages=%d ordered=%v, want 2/false", len(sr.stages), sr.ordered)
	}

	se := NewSequenceEngine()
	se.LoadRules([]*DetectionRule{stagedRule("wmilat", shippedWMILateralKillChainContent)})

	m := se.Observe("h1", "wmi_activity", map[string]any{"wmi_consumer_type": "CommandLineEventConsumer"})
	if hasMatch(m, "wmilat") {
		t.Fatal("fired after the WMI-persistence stage alone")
	}
	m = se.Observe("h1", "named_pipe", map[string]any{"pipe_name": `\PSEXESVC`})
	if !hasMatch(m, "wmilat") {
		t.Fatal("shipped WMI+lateral kill-chain rule did not fire on wmi_activity -> named_pipe")
	}
}

// The unordered rule must also fire lateral-movement-first (real intrusions do
// not always establish persistence before moving laterally).
func TestShippedWMILateralKillChainRule_FiresLateralFirst(t *testing.T) {
	se := NewSequenceEngine()
	se.LoadRules([]*DetectionRule{stagedRule("wmilat", shippedWMILateralKillChainContent)})

	se.Observe("h1", "named_pipe", map[string]any{"pipe_name": `\msagent_a1`})
	m := se.Observe("h1", "wmi_activity", map[string]any{"wmi_consumer_type": "ActiveScriptEventConsumer"})
	if !hasMatch(m, "wmilat") {
		t.Fatal("shipped WMI+lateral kill-chain rule did not fire lateral-first (unordered)")
	}
}

// shippedCredDumpInjectionKillChainContent mirrors the rule body in migration
// 319_killchain_creddump_injection.sql. Keep in sync.
const shippedCredDumpInjectionKillChainContent = `
window: 15m
stages: 2
ordered: true
stage_1_event_type: credential_access
stage_1_field: target_image
stage_1: lsass.exe
stage_2_event_type: create_remote_thread
stage_2_field: target_image
stage_2: lsass.exe, winlogon.exe, csrss.exe, services.exe, svchost.exe
group_by: agent_id
`

func TestShippedCredDumpInjectionKillChainRule_Fires(t *testing.T) {
	sr, err := parseSequenceRule(stagedRule("creddmp", shippedCredDumpInjectionKillChainContent))
	if err != nil {
		t.Fatalf("shipped creddump+injection kill-chain rule failed to parse: %v", err)
	}
	if len(sr.stages) != 2 || !sr.ordered {
		t.Fatalf("shipped rule parsed as stages=%d ordered=%v, want 2/true", len(sr.stages), sr.ordered)
	}

	se := NewSequenceEngine()
	se.LoadRules([]*DetectionRule{stagedRule("creddmp", shippedCredDumpInjectionKillChainContent)})

	m := se.Observe("h1", "credential_access", map[string]any{"target_image": `C:\Windows\System32\lsass.exe`})
	if hasMatch(m, "creddmp") {
		t.Fatal("fired after the LSASS-access stage alone")
	}
	m = se.Observe("h1", "create_remote_thread", map[string]any{"target_image": `C:\Windows\System32\svchost.exe`})
	if !hasMatch(m, "creddmp") {
		t.Fatal("shipped creddump+injection kill-chain rule did not fire on credential_access -> create_remote_thread")
	}
}

// Order matters for this rule (dump-then-inject, not inject-then-dump).
func TestShippedCredDumpInjectionKillChainRule_WrongOrderNoFire(t *testing.T) {
	se := NewSequenceEngine()
	se.LoadRules([]*DetectionRule{stagedRule("creddmp", shippedCredDumpInjectionKillChainContent)})

	se.Observe("h1", "create_remote_thread", map[string]any{"target_image": `C:\Windows\System32\svchost.exe`})
	m := se.Observe("h1", "credential_access", map[string]any{"target_image": `C:\Windows\System32\lsass.exe`})
	if hasMatch(m, "creddmp") {
		t.Fatal("ordered kill chain fired with injection observed before credential access")
	}
}

// A thread injected into a NON-system target must not satisfy stage 2 — the
// target_image gate exists to distinguish "injection into a critical process"
// from ordinary cross-process thread noise.
func TestShippedCredDumpInjectionKillChainRule_NonSystemTargetNoFire(t *testing.T) {
	se := NewSequenceEngine()
	se.LoadRules([]*DetectionRule{stagedRule("creddmp", shippedCredDumpInjectionKillChainContent)})

	se.Observe("h1", "credential_access", map[string]any{"target_image": `C:\Windows\System32\lsass.exe`})
	m := se.Observe("h1", "create_remote_thread", map[string]any{"target_image": `C:\Users\victim\AppData\Local\Temp\notepad.exe`})
	if hasMatch(m, "creddmp") {
		t.Fatal("kill chain fired for injection into a non-system-process target")
	}
}

func TestStagedRuleParsing_PerStageOverrides(t *testing.T) {
	sr, err := parseSequenceRule(stagedRule("xt", crossTypeKillChainContent))
	if err != nil {
		t.Fatalf("cross-event-type staged rule failed to parse: %v", err)
	}
	if len(sr.stages) != 2 {
		t.Fatalf("got %d stages, want 2", len(sr.stages))
	}
	if sr.stages[0].eventType != "wmi_activity" || sr.stages[0].field != "wmi_consumer_type" {
		t.Errorf("stage 1 overrides = %+v", sr.stages[0])
	}
	if sr.stages[1].eventType != "named_pipe" || sr.stages[1].field != "pipe_name" {
		t.Errorf("stage 2 overrides = %+v", sr.stages[1])
	}
}
