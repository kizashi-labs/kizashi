package detection

import (
	"strings"
	"testing"
)

// TestTypedFindings is the regression suite for the non-Sigma detection sources
// (DNS heuristics, agent YARA/threat-intel verdicts, memory & credential-access
// findings) that live in engine.typedFindings. It guards the silent-break class
// found in 2026-06: a source whose match carried a non-UUID RuleID failed the
// uuid-typed alerts.rule_id INSERT and produced ZERO alerts unnoticed, and a
// source whose field alias was dropped never fired. Each case asserts the source
// FIRES on representative telemetry; a cross-cutting check asserts every match is
// well-formed (empty RuleID, an ATT&CK technique, a RuleType).
func TestTypedFindings(t *testing.T) {
	cases := []struct {
		name      string
		eventType string
		event     map[string]interface{}
		wantFire  bool
		wantType  string // expected RuleType of the (first) match when wantFire
	}{
		{
			name:      "dns DGA domain",
			eventType: "dns",
			event:     map[string]interface{}{"query": "kq3v9z7x1p.com"},
			wantFire:  true, wantType: "heuristic",
		},
		{
			name:      "dns benign domain",
			eventType: "dns",
			event:     map[string]interface{}{"query": "google.com"},
			wantFire:  false,
		},
		{
			name:      "dns agent is_suspicious verdict on an otherwise-benign-looking query",
			eventType: "dns",
			event:     map[string]interface{}{"query": "paypa1.com", "is_suspicious": true},
			wantFire:  true, wantType: "heuristic",
		},
		{
			name:      "dns benign query without agent verdict fires nothing",
			eventType: "dns",
			event:     map[string]interface{}{"query": "paypa1.com"},
			wantFire:  false,
		},
		{
			name:      "agent yara verdict",
			eventType: "file",
			event:     map[string]interface{}{"yara_matched": true, "yara_rule_ids": []interface{}{"EICAR"}},
			wantFire:  true, wantType: "yara",
		},
		{
			name:      "agent threat-intel verdict",
			eventType: "network",
			event:     map[string]interface{}{"threat_intel_matched": true, "threat_intel_category": "c2", "threat_intel_source": "feed"},
			wantFire:  true, wantType: "ioc",
		},
		{
			name:      "memory finding",
			eventType: "memory",
			event:     map[string]interface{}{"process_name": "evil.exe", "reason": "RWX unbacked region", "address": "0x1000", "unbacked": true},
			wantFire:  true, wantType: "memory",
		},
		{
			// Benign floating-code FP: an unbacked, non-writable (r-x) region in a
			// known-benign system daemon (unattended-upgrades) with no YARA hit — a
			// scanner artifact (~3.6k/7d). Suppressed.
			name:      "memory benign daemon unbacked r-x is suppressed",
			eventType: "memory",
			event:     map[string]interface{}{"process_name": "unattended-upgr", "reason": "非バック実行領域", "address": "62d3c3b37000-62d3c3dec000", "unbacked": true, "rwx": false, "perms": "r-xp", "yara_matched": false},
			wantFire:  false,
		},
		{
			// Same benign daemon but a currently writable+executable (W^X) region —
			// the strong injection signal is NEVER gated. Must fire.
			name:      "memory benign daemon RWX still fires",
			eventType: "memory",
			event:     map[string]interface{}{"process_name": "unattended-upgr", "reason": "RWX領域", "address": "0x2000", "unbacked": true, "rwx": true, "perms": "rwxp", "yara_matched": false},
			wantFire:  true, wantType: "memory",
		},
		{
			// Unbacked r-x in a NON-allowlisted process still fires (only known-benign
			// daemons are gated).
			name:      "memory unknown process unbacked r-x still fires",
			eventType: "memory",
			event:     map[string]interface{}{"process_name": "sshd", "reason": "非バック実行領域", "address": "0x3000", "unbacked": true, "rwx": false, "perms": "r-xp", "yara_matched": false},
			wantFire:  true, wantType: "memory",
		},
		{
			name:      "credential access (lsass VM_READ)",
			eventType: "credential_access",
			event:     map[string]interface{}{"source_image": "mimikatz.exe", "source_pid": 1234, "target_pid": 856, "access_mask": "0x1410"},
			wantFire:  true, wantType: "credential_access",
		},
		{
			// Linux ptrace ATTACH mode (0x06 = ATTACH|NOAUDIT|FSCREDS): the actual
			// mem-read primitive (process_vm_readv / /proc/pid/mem). Non-benign
			// accessor → must fire.
			name:      "credential access (linux ptrace ATTACH mem read)",
			eventType: "credential_access",
			event:     map[string]interface{}{"source_image": "python3", "source_pid": 2222, "target_image": "sshd", "target_pid": 900, "access_mask": "ptrace_mode=0x06"},
			wantFire:  true, wantType: "credential_access",
		},
		{
			// Linux ptrace READ mode (0x0d = READ|NOAUDIT|FSCREDS, no ATTACH bit):
			// the benign /proc-enumeration firehose (`ps` scanning every pid). This
			// is the ~97k/7d FP class — must NOT fire.
			name:      "credential access (linux ps /proc READ enumeration is suppressed)",
			eventType: "credential_access",
			event:     map[string]interface{}{"source_image": "ps", "source_pid": 3133085, "target_image": "kworker/0:2", "target_pid": 3132301, "access_mask": "ptrace_mode=0xd"},
			wantFire:  false,
		},
		{
			// ATTACH mode but a known-benign system tracer (runc container setup) —
			// still suppressed by isBenignLinuxTracer.
			name:      "credential access (linux benign tracer ATTACH suppressed)",
			eventType: "credential_access",
			event:     map[string]interface{}{"source_image": "runc:[2:INIT]", "source_pid": 4444, "target_image": "bash", "target_pid": 4445, "access_mask": "ptrace_mode=0x06"},
			wantFire:  false,
		},
		{
			name:      "process_block prevention surfaces a BLOCKED alert",
			eventType: "process_block",
			event: map[string]interface{}{
				"process_name": "evil.exe", "pid": 4321, "action": "killed",
				"rule_name": "ランサム挙動", "severity": float64(9),
			},
			wantFire: true, wantType: "process_block",
		},
		{
			name:      "removable storage connect surfaces a DEVICE alert",
			eventType: "device_event",
			event: map[string]interface{}{
				"action": "connected", "type": "storage",
				"name": "SanDisk Cruzer", "vendor_id": "0781", "product_id": "5567",
			},
			wantFire: true, wantType: "device_event",
		},
		{
			name:      "USB input device connect fires nothing (keyboard/mouse noise)",
			eventType: "device_event",
			event: map[string]interface{}{
				"action": "connected", "type": "input", "name": "USB Keyboard",
			},
			wantFire: false,
		},
		{
			name:      "device disconnect fires nothing",
			eventType: "device_event",
			event: map[string]interface{}{
				"action": "disconnected", "type": "storage", "name": "SanDisk Cruzer",
			},
			wantFire: false,
		},
		{
			name:      "benign process event fires nothing",
			eventType: "process",
			event:     map[string]interface{}{"process_name": "notepad.exe"},
			wantFire:  false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			matches := typedFindings(c.eventType, c.event)
			if c.wantFire && len(matches) == 0 {
				t.Fatalf("expected a match for %s, got none", c.name)
			}
			if !c.wantFire && len(matches) > 0 {
				t.Fatalf("expected no match for %s, got %d (%s)", c.name, len(matches), matches[0].RuleName)
			}
			if c.wantFire && matches[0].RuleType != c.wantType {
				t.Errorf("RuleType = %q, want %q", matches[0].RuleType, c.wantType)
			}
			// Cross-cutting well-formedness — the silent-break guards.
			for _, m := range matches {
				if m.RuleID != "" {
					t.Errorf("%s: RuleID=%q must be empty (alerts.rule_id is uuid-typed; a non-UUID string fails the INSERT)", c.name, m.RuleID)
				}
				if len(m.MITRETags) == 0 {
					t.Errorf("%s: match %q has no ATT&CK technique", c.name, m.RuleName)
				}
				if m.RuleType == "" {
					t.Errorf("%s: match %q has no RuleType", c.name, m.RuleName)
				}
				if !strings.HasPrefix(m.Title, "[") {
					t.Errorf("%s: title %q should carry a [SOURCE] tag", c.name, m.Title)
				}
			}
		})
	}
}
