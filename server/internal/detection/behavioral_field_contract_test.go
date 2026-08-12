package detection

import (
	"strings"
	"testing"
)

// TestBehavioralRuleFieldContract is the root-cause gate for the recurring silent
// failure this session surfaced repeatedly: a behavioral (SequenceEngine) rule
// that references an event field the flattened telemetry never populates is
// permanently inert (it never fires, un-noticed). The auth eventName rules
// (value:4625 on a non-existent field) and the network dstIp/dstPort/srcIp rules
// (camelCase names absent from the snake_case flat) both belonged to this class —
// all had ever_fired=0 in production.
//
// This test pins the field-name contract: every field a behavioral rule reads must
// be in SupportedSigmaFields() (the SequenceEngine sees the SAME aliased flat map
// as Sigma evaluation). It fails loudly if a future rule references an unsupported
// field, or if the alias layer drops a field a shipped rule depends on.
func TestBehavioralRuleFieldContract(t *testing.T) {
	supported := SupportedSigmaFields()

	// Corpus mirrors the shipped builtin behavioral rules (migrations 004/266/272/
	// 288/290/291) plus the two known-broken shapes as negative controls. Keep in
	// sync with the rules table; each entry is (name, content, wantSupported).
	cases := []struct {
		name          string
		content       string
		wantSupported bool
	}{
		// ── Working rules (fields present in the aliased flat) ──
		{"discovery burst", "window: 60s\nthreshold: 4\nevent_type: process\nfield: processName\ndistinct: true\ndistinct_field: processName", true},
		{"hands-on kill chain", "window: 10m\nstages: 3\nordered: true\nevent_type: process\nfield: commandLine\nstage_1: whoami\nstage_2: reg save\nstage_3: psexec", true},
		{"ransomware encrypt", "window: 60s\nthreshold: 30\nevent_type: file\nfield: path\ndistinct: true\ndistinct_field: path", true},
		{"dns c2", "window: 60s\nthreshold: 10\nevent_type: dns\nfield: query\ndistinct: true\ndistinct_field: query", true},
		{"process burst (no field)", "window: 5s\nthreshold: 20\nevent_type: process\ngroup_by: agent_id", true},
		// ── Fixed auth rules (migration 288: action/source_ip) ──
		{"auth brute per-user", "window: 120s\nthreshold: 8\nevent_type: auth\nfield: action\nvalue: failed\ngroup_by: username", true},
		{"password spray", "window: 300s\nthreshold: 5\nevent_type: auth\nfield: action\nvalue: failed\ngroup_by: source_ip\ndistinct: true\ndistinct_field: username", true},
		// ── Fixed network rules (migration 291: dst_port/src_ip/dst_ip) ──
		{"rdp brute (fixed)", "window: 30s\nthreshold: 8\nevent_type: network\nfield: dst_port\nvalue: 3389\ngroup_by: src_ip", true},
		{"port scan (fixed)", "window: 10s\nthreshold: 15\nevent_type: network\ndistinct: true\ndistinct_field: dst_port\ngroup_by: src_ip", true},
		{"internal recon (fixed)", "window: 30s\nthreshold: 20\nevent_type: network\ndistinct: true\ndistinct_field: dst_ip\ngroup_by: agent_id", true},

		// ── Negative controls: the pre-fix broken shapes MUST be flagged ──
		{"BROKEN auth eventName", "window: 120s\nthreshold: 10\nevent_type: auth\nfield: eventName\nvalue: 4625\ngroup_by: agent_id", false},
		{"BROKEN network dstPort/srcIp", "window: 30s\nthreshold: 8\nevent_type: network\nfield: dstPort\ngroup_by: srcIp", false},
		{"BROKEN network dstIp", "window: 30s\nthreshold: 20\nevent_type: network\ndistinct: true\ndistinct_field: dstIp\ngroup_by: agent_id", false},
	}

	for _, c := range cases {
		ok, unsupported := BehavioralRuleFieldSupportWith(c.content, supported)
		if ok != c.wantSupported {
			t.Errorf("%q: field-support = %v (want %v); unsupported fields = %v",
				c.name, ok, c.wantSupported, unsupported)
		}
		// A shipped rule (wantSupported) that regresses names exactly which field
		// the alias layer must expose — make that actionable.
		if c.wantSupported && !ok {
			t.Errorf("%q references field(s) not in the flat map: %s — the rule is INERT "+
				"(add an alias in addPipelineSigmaAliases or fix the rule field)",
				c.name, strings.Join(unsupported, ", "))
		}
	}
}
