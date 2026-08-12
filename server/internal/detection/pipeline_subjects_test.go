package detection

import (
	"sort"
	"strings"
	"testing"
)

// The AlertPipeline is the only evaluator that loads the built-in Sigma rule
// set, so its NATS subject filter decides which rules can fire AT ALL. An event
// type missing from it makes every built-in rule targeting that type
// structurally dark: the sensor emits, ingestion publishes, the DB stores it,
// and the rule is never reached. That is not a rule-content bug and no amount of
// rule testing finds it — it was found by a live WMI validation (2026-07-10)
// where wmi_activity events demonstrably arrived and the T1546.003 rule still
// never evaluated.
//
// These tests pin the subject list to eventTypeCategories (sigma_category.go),
// which is maintained against the rule corpus as "the event types a built-in
// rule may legitimately match". Pinning to the derivation rather than to a
// literal list is the point: a hand-written copy is exactly what drifted to four
// entries while the rule corpus grew to fourteen.
func TestPipelineSubjectsCoverEveryRuleReachableEventType(t *testing.T) {
	have := make(map[string]bool, len(pipelineSubjects))
	for _, s := range pipelineSubjects {
		have[s] = true
	}
	for evType := range eventTypeCategories {
		want := "events.*." + evType
		if !have[want] {
			t.Errorf("pipelineSubjects missing %q — built-in rules for %q can never fire (event filtered out before evaluation)", want, evType)
		}
	}
}

// The converse: a subject with no entry in eventTypeCategories means the
// pipeline pays to evaluate events no built-in rule can match. categoryCompatible
// treats such a type as incompatible with every declared category, so those
// events would also generate a shadow-mode mismatch warning apiece.
func TestPipelineSubjectsHaveNoUnmatchableExtras(t *testing.T) {
	for _, s := range pipelineSubjects {
		evType := strings.TrimPrefix(s, "events.*.")
		if _, ok := eventTypeCategories[evType]; !ok {
			t.Errorf("subject %q has no eventTypeCategories entry — no built-in rule can match it", s)
		}
	}
}

// The exclusions are as deliberate as the inclusions. process_stats is a
// per-process periodic snapshot and process_block is an already-decided finding:
// both are high-rate and carry no Sigma rules, so subscribing to them would cost
// throughput for zero detection — and a pipeline that falls behind is how the
// detection-engine ended up chronically lagging in the first place. Subscribing
// to the raw "events.>" wildcard would pull in all of it at once.
func TestPipelineSubjectsExcludeRuleFreeFirehoses(t *testing.T) {
	have := make(map[string]bool, len(pipelineSubjects))
	for _, s := range pipelineSubjects {
		have[s] = true
	}
	for _, excluded := range []string{"events.*.process_stats", "events.*.process_block", "events.*.resource_usage", "events.>"} {
		if have[excluded] {
			t.Errorf("pipelineSubjects unexpectedly includes %q — high-rate, rule-free stream must stay excluded", excluded)
		}
	}
}

// Every event type the pipeline subscribes to must survive the flatten path the
// live handler uses. This is the end-to-end half of the fix: subscribing to
// create_remote_thread achieves nothing if the rule that consumes it is never
// loaded (sigma_db.go) or if flattening loses the fields it reads.
//
// "Process Hollowing via Suspicious Executable" (T1055.012, severity 9 +
// auto-isolate) is the confirmed case — it lives only in the `rules` table, so
// it was un-loaded on the real-time path AND un-reached on the lagging one.
func TestProcessHollowingFiresOnLivePath(t *testing.T) {
	// The rule as seeded in migration 019 (rules table, type='sigma').
	const rule = `title: Process Hollowing via Suspicious Executable
id: a1b2c3d4-0006-0006-0006-000000000028
status: experimental
description: Detects process hollowing
logsource:
  category: create_remote_thread
  product: windows
detection:
  selection:
    TargetImage|endswith:
      - '\svchost.exe'
      - '\explorer.exe'
      - '\notepad.exe'
      - '\regsvr32.exe'
    SourceImage|startswith:
      - 'C:\Users\'
      - 'C:\Temp\'
      - 'C:\ProgramData\'
  condition: selection
level: critical`

	e := NewSigmaEvaluator()
	if err := e.LoadRule(rule); err != nil {
		t.Fatalf("LoadRule: %v", err)
	}

	// The NormalizedEvent envelope as published to NATS by ingestion: top-level
	// metadata plus a nested data payload carrying the injection sensor fields.
	envelope := map[string]interface{}{
		"agent_id": "11111111-1111-1111-1111-111111111111",
		"hostname": "WIN-BOX",
		"platform": "windows",
		"type":     "create_remote_thread",
		"data": map[string]interface{}{
			"source_image": `C:\Users\v\AppData\Local\Temp\rtinject.exe`,
			"target_image": `C:\Windows\System32\notepad.exe`,
			"source_pid":   "4242",
			"target_pid":   "9001",
		},
	}
	flat := flattenNormalizedEvent(envelope)

	found := false
	for _, m := range e.EvaluateEvent(flat) {
		if strings.Contains(m.RuleTitle, "Process Hollowing") {
			found = true
		}
	}
	if !found {
		t.Errorf("Process Hollowing rule did not match on the live flatten path; flat=%v", flat)
	}
}

// The published subject shape is events.<agentID>.<type>. The wildcard must be
// the middle token: a filter like "events.process" or "events.agent-1.process"
// silently matches nothing, or only one agent's events.
func TestPipelineSubjectsAreAgentWildcarded(t *testing.T) {
	for _, s := range pipelineSubjects {
		if !strings.HasPrefix(s, "events.*.") {
			t.Errorf("subject %q must be events.*.<type>", s)
		}
		if strings.Count(s, ".") != 2 {
			t.Errorf("subject %q must have exactly three tokens (events.*.<type>)", s)
		}
	}
}

// FilterSubjects is part of the durable consumer's stored config. Map iteration
// order is randomized per run, so an unsorted list would make every restart look
// like a consumer config change to NATS.
func TestPipelineSubjectsAreStablySorted(t *testing.T) {
	if !sort.StringsAreSorted(pipelineSubjects) {
		t.Errorf("pipelineSubjects must be sorted for a stable durable-consumer config; got %v", pipelineSubjects)
	}
}
