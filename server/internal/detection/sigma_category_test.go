package detection

import "testing"

func TestCategoryCompatible(t *testing.T) {
	cases := []struct {
		name       string
		eventType  string
		ruleCat    string
		compatible bool
	}{
		{"process/process_creation matches", "process", "process_creation", true},
		{"registry/registry_event matches", "registry", "registry_event", true},
		{"file covers file_event", "file", "file_event", true},
		{"file covers file_access", "file", "file_access", true},
		{"credential_access maps to process_access", "credential_access", "process_access", true},
		{"named_pipe maps to pipe_created", "named_pipe", "pipe_created", true},
		{"wmi_activity maps to wmi_event", "wmi_activity", "wmi_event", true},
		{"empty rule category is always compatible", "image_load", "", true},
		{"empty rule category compatible with unknown type too", "totally_unknown_type", "", true},
		{"network_connection rule vs image_load event mismatches (the 2026-07-20 live bug)", "image_load", "network_connection", false},
		{"process_creation rule vs registry event mismatches", "registry", "process_creation", false},
		{"unknown event type is incompatible with any declared category", "process_block", "process_creation", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := categoryCompatible(tc.eventType, tc.ruleCat)
			if got != tc.compatible {
				t.Errorf("categoryCompatible(%q, %q) = %v, want %v", tc.eventType, tc.ruleCat, got, tc.compatible)
			}
		})
	}
}

// TestEvaluateEvent_CategoryMismatchIsShadowOnly locks in the P4-9 shadow-mode
// contract: a category mismatch must be logged/counted, never used to drop a
// match. Reproduces the live 2026-07-20 shape (a network_connection-scoped
// rule matching purely on a shared field name against an image_load event).
func TestEvaluateEvent_CategoryMismatchIsShadowOnly(t *testing.T) {
	rule := `
title: Network rule with a field that also appears on image_load events
level: medium
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    Image|endswith: \notepad.exe
  condition: selection
`
	e := loadOne(t, rule)
	event := map[string]interface{}{
		"type":  "image_load", // NOT network_connection -- the mismatch under test
		"Image": `C:\Windows\System32\notepad.exe`,
	}
	if !matched(e, event) {
		t.Fatal("shadow mode must NOT filter a category-mismatched match -- expected the rule to still fire")
	}
}

func TestEvaluateEvent_CategoryMatchStillFires(t *testing.T) {
	rule := `
title: Process rule
level: medium
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: \cmd.exe
  condition: selection
`
	e := loadOne(t, rule)
	event := map[string]interface{}{
		"type":  "process",
		"Image": `C:\Windows\System32\cmd.exe`,
	}
	if !matched(e, event) {
		t.Fatal("expected a category-compatible match to fire")
	}
}
