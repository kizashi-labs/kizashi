package detection

import "testing"

// A staged kill chain with per-stage event_type/field overrides
// (stage_N_field, added for cross-event-type kill chains — see
// rules/sequence_staged_crosstype_test.go) must have those fields picked up by
// the field-support audit. Without this, a rule referencing e.g.
// stage_1_field: wmi_consumer_type would report "no fields referenced" and
// silently escape the inert-rule gate that field_support.go exists to enforce.
func TestBehavioralRuleReferencedFields_StageOverrides(t *testing.T) {
	content := `
window: 10m
stages: 2
ordered: true
stage_1_event_type: wmi_activity
stage_1_field: wmi_consumer_type
stage_1: commandlineeventconsumer
stage_2_event_type: named_pipe
stage_2_field: pipe_name
stage_2: psexesvc
group_by: agent_id
`
	fields := BehavioralRuleReferencedFields(content)
	got := map[string]bool{}
	for _, f := range fields {
		got[f] = true
	}
	for _, want := range []string{"wmi_consumer_type", "pipe_name"} {
		if !got[want] {
			t.Errorf("BehavioralRuleReferencedFields missed stage override field %q; got %v", want, fields)
		}
	}
}

// A stage override naming a field no sensor populates must be reported as
// unsupported. wmi_consumer_type is exactly that case today: the WMI-Activity
// ETW sensor is not in the tree, so a kill chain reading that field would be
// permanently inert. Asserting the negative here keeps the guarantee honest —
// declaring the field "supported" to make a rule look healthy is the false-green
// pattern that left rules silently dead before (see 技術的負債と改善計画.md P5-7).
//
// When the WMI-Activity sensor lands, wmi_consumer_type joins the supported set
// and this expectation flips — that is the intended signal to enable the
// wmi_activity kill chain, which is being held back for the same reason.
func TestBehavioralRuleFieldSupport_StageOverrideWithoutSensorIsUnsupported(t *testing.T) {
	content := `
window: 10m
stages: 2
ordered: true
stage_1_event_type: wmi_activity
stage_1_field: wmi_consumer_type
stage_1: commandlineeventconsumer
stage_2_event_type: named_pipe
stage_2_field: pipe_name
stage_2: psexesvc
group_by: agent_id
`
	supported, unsupported := BehavioralRuleFieldSupportWith(content, SupportedSigmaFields())
	if supported {
		t.Fatalf("wmi_consumer_type has no telemetry source yet, so the rule must be flagged unsupported")
	}
	found := false
	for _, f := range unsupported {
		if f == "wmi_consumer_type" {
			found = true
		}
		// named_pipe's field does have a sensor (pipe_etw.go), so it must not be
		// swept up in the unsupported set.
		if f == "pipe_name" {
			t.Errorf("pipe_name has a sensor and must not be reported unsupported; got %v", unsupported)
		}
	}
	if !found {
		t.Errorf("expected wmi_consumer_type in unsupported=%v", unsupported)
	}
}
