package detection

import (
	"slices"
	"testing"
)

// TestRuleFieldSupport is the curate gate: it decides whether a SigmaHQ-synced
// rule is safe to enable (every selected field is populated by live telemetry) or
// must stay pending (selects on a field the agent never emits → inert "false
// green"). Now that the detection-server normalizes registry/image_load/script/
// Hashes fields (P1 Phase A), rules in those categories are supportable.
func TestRuleFieldSupport(t *testing.T) {
	cases := []struct {
		name          string
		rule          string
		wantSupported bool
		wantUnsupp    []string // subset that must appear in the unsupported list
	}{
		{
			name: "process_creation on supported fields",
			rule: `
title: Encoded PowerShell
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains: '-enc'
  condition: selection`,
			wantSupported: true,
		},
		{
			name: "registry rule is supportable after Phase A (TargetObject)",
			rule: `
title: Run Key Persistence
detection:
  selection:
    TargetObject|contains: '\CurrentVersion\Run'
    Details|endswith: '.exe'
  condition: selection`,
			wantSupported: true,
		},
		{
			name: "image_load rule is supportable after Phase A",
			rule: `
title: Unsigned DLL sideload
detection:
  selection:
    ImageLoaded|endswith: '.dll'
    Signed: 'false'
  condition: selection`,
			wantSupported: true,
		},
		{
			name: "script rule is supportable after Phase A",
			rule: `
title: Obfuscated PowerShell
detection:
  selection:
    ScriptBlockText|contains: 'FromBase64String'
  condition: selection`,
			wantSupported: true,
		},
		{
			name: "rule selecting a field telemetry never emits is inert",
			rule: `
title: Needs Sysmon EID10 GrantedAccess
detection:
  selection:
    GrantedAccess: '0x1410'
    CallTrace|contains: 'UNKNOWN'
  condition: selection`,
			wantSupported: false,
			wantUnsupp:    []string{"GrantedAccess", "CallTrace"},
		},
		{
			name:          "unparseable / empty rule is never enabled",
			rule:          `: not valid yaml :::`,
			wantSupported: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			supported, unsupp := RuleFieldSupport(c.rule)
			if supported != c.wantSupported {
				t.Fatalf("supported = %v, want %v (unsupported fields: %v)", supported, c.wantSupported, unsupp)
			}
			for _, want := range c.wantUnsupp {
				if !slices.Contains(unsupp, want) {
					t.Errorf("expected %q in unsupported list, got %v", want, unsupp)
				}
			}
		})
	}
}

// TestRuleFieldSupportORAware verifies the gate treats a rule as supported when
// it can FIRE on a supported branch, even if an alternative or negated branch
// references a field the agent never emits (the registry-rename NewName class).
// It must still reject rules whose only firing path needs an unsupported field.
func TestRuleFieldSupportORAware(t *testing.T) {
	cases := []struct {
		name          string
		rule          string
		wantSupported bool
	}{
		{
			// SigmaHQ "Disable Security Events Logging (MiniNt)" shape: an OR-list
			// selection whose first element (TargetObject+EventType) is supported and
			// second element (NewName, registry rename) is not. Fires on the first.
			name: "OR-list selection with one supported branch is supported",
			rule: `
title: MiniNt
detection:
  selection:
    - TargetObject: 'HKLM\SYSTEM\CurrentControlSet\Control\MiniNt'
      EventType: 'CreateKey'
    - NewName: 'HKLM\SYSTEM\CurrentControlSet\Control\MiniNt'
  condition: selection`,
			wantSupported: true,
		},
		{
			// "Registry Persistence in Recycle Bin": 1 of selection_* where
			// selection_set (SetValue+TargetObject) is supported, selection_create
			// (RenameKey+NewName) is not.
			name: "1 of selection_* with one supported branch is supported",
			rule: `
title: Recycle Bin persistence
detection:
  selection_create:
    EventType: RenameKey
    NewName|contains: '\CLSID\{645FF040}\shell\open'
  selection_set:
    EventType: SetValue
    TargetObject|contains: '\CLSID\{645FF040}\shell\open\command'
  condition: 1 of selection_*`,
			wantSupported: true,
		},
		{
			// "AppInit_DLLs": OR-list selection (TargetObject supported / NewName not)
			// AND NOT filter — the negated filter never makes the rule inert.
			name: "selection and not filter with unsupported field in negated branch",
			rule: `
title: AppInit_DLLs
detection:
  selection:
    - TargetObject|endswith: '\Windows\AppInit_Dlls'
    - NewName|endswith: '\Windows\AppInit_Dlls'
  filter:
    Details: '(Empty)'
  condition: selection and not filter`,
			wantSupported: true,
		},
		{
			// Every firing path needs NewName (no supported alternative) → still inert.
			name: "only branch needs an unsupported field is inert",
			rule: `
title: Pure rename
detection:
  selection:
    EventType: RenameKey
    NewName|contains: '\Run'
  condition: selection`,
			wantSupported: false,
		},
		{
			// all of selection_* requires BOTH; one needs an unsupported field → inert.
			name: "all of selection_* with an unsupported branch is inert",
			rule: `
title: Needs both
detection:
  selection_a:
    TargetObject|contains: '\Run'
  selection_b:
    NewName|contains: '\Run'
  condition: all of selection_*`,
			wantSupported: false,
		},
		{
			// "Publicly Accessible RDP Service" shape (Zeek-only field id.orig_h):
			// a bare negation with no accompanying positive term. At runtime a
			// selection on a field that is never populated never matches, so
			// `not selection` is unconditionally true for every event of any
			// type — not a working "fires on supported fields" detection.
			name: "bare negation over an entirely unsupported field is inert",
			rule: `
title: Publicly Accessible RDP Service
detection:
  selection:
    id.orig_h|cidr:
      - '10.0.0.0/8'
  condition: not selection`,
			wantSupported: false,
		},
		{
			// Same bare-negation shape, but the referenced field IS supported —
			// this is a legitimate "alert unless private/known" pattern and must
			// still be enabled.
			name: "bare negation over a supported field is still supported",
			rule: `
title: External source IP
detection:
  selection:
    src_ip|cidr:
      - '10.0.0.0/8'
  condition: not selection`,
			wantSupported: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			supported, unsupp := RuleFieldSupport(c.rule)
			if supported != c.wantSupported {
				t.Errorf("supported = %v, want %v (unsupported fields: %v)", supported, c.wantSupported, unsupp)
			}
		})
	}
}

// TestRuleFieldSupportWith_SharesSet verifies the batch form returns the same
// verdict as the convenience form (curate computes the supported set once and
// reuses it across thousands of synced rules).
func TestRuleFieldSupportWith_SharesSet(t *testing.T) {
	set := SupportedSigmaFields()
	rule := `
title: x
detection:
  selection:
    CommandLine|contains: 'whoami'
  condition: selection`
	a, _ := RuleFieldSupport(rule)
	b, _ := RuleFieldSupportWith(rule, set)
	if a != b || !b {
		t.Fatalf("batch and convenience forms disagree: convenience=%v batch=%v", a, b)
	}
}
