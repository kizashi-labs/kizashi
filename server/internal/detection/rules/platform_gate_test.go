package rules

import (
	"context"
	"testing"
)

// ─── pure helper ─────────────────────────────────────────────────────────────

func TestCanonPlatform(t *testing.T) {
	cases := map[string]string{
		"linux": "linux", "Linux": "linux",
		"windows": "windows", "WINDOWS": "windows", "win": "windows",
		"macos": "macos", "macOS": "macos", "darwin": "macos", "osx": "macos", "mac": "macos",
		" darwin ": "macos", // trimmed
		"unknown":  "", "": "", "solaris": "",
	}
	for in, want := range cases {
		if got := canonPlatform(in); got != want {
			t.Errorf("canonPlatform(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPlatformMatchesEvent(t *testing.T) {
	tests := []struct {
		name     string
		rulePlat []string
		eventPl  string
		want     bool
	}{
		{"no platform = universal", nil, "linux", true},
		{"all-three universal on linux", []string{"windows", "linux", "macos"}, "linux", true},
		{"macos rule on linux event → gated", []string{"macos"}, "linux", false},
		{"macos rule on darwin event → match (darwin≡macos)", []string{"macos"}, "darwin", true},
		{"linux rule on linux event", []string{"linux"}, "linux", true},
		{"windows rule on linux event → gated", []string{"windows"}, "linux", false},
		{"unknown event OS → fail-open", []string{"macos"}, "unknown", true},
		{"empty event OS → fail-open", []string{"macos"}, "", true},
		{"multi-os rule includes event", []string{"linux", "macos"}, "darwin", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := platformMatchesEvent(tc.rulePlat, tc.eventPl); got != tc.want {
				t.Errorf("platformMatchesEvent(%v, %q) = %v, want %v", tc.rulePlat, tc.eventPl, got, tc.want)
			}
		})
	}
}

// ─── integration: the actual FP the gate fixes ──────────────────────────────

// A MacOS-only discovery rule (the real FP: "File and Directory Discovery -
// MacOS") must not fire on Linux telemetry, but must still fire on macOS
// (reported as "darwin" by the agent).
func TestRuleEngine_PlatformGate_MacosRuleDoesNotMatchLinux(t *testing.T) {
	const content = `
title: File and Directory Discovery - MacOS
level: low
detection:
  selection:
    Image|endswith: /ls
  condition: selection
`
	rule := &DetectionRule{
		ID: "macos-disc", Name: "File and Directory Discovery - MacOS", Type: "sigma",
		Enabled: true, Severity: 30, Platform: []string{"macos"}, Content: content,
	}
	e := NewRuleEngine()
	e.LoadRules([]*DetectionRule{rule})

	linuxEvt := map[string]interface{}{
		"type": "process", "agent_id": "host-linux", "platform": "linux",
		"imagePath": "/usr/bin/ls",
	}
	if m, err := e.Evaluate(context.Background(), linuxEvt); err != nil {
		t.Fatalf("Evaluate: %v", err)
	} else if hasRule(m, "macos-disc") {
		t.Fatalf("MacOS rule should be gated on a Linux event, but matched")
	}

	darwinEvt := map[string]interface{}{
		"type": "process", "agent_id": "host-mac", "platform": "darwin",
		"imagePath": "/bin/ls",
	}
	if m, err := e.Evaluate(context.Background(), darwinEvt); err != nil {
		t.Fatalf("Evaluate: %v", err)
	} else if !hasRule(m, "macos-disc") {
		t.Fatalf("MacOS rule should match a darwin (macOS) event, but was gated")
	}
}

// With the gate disabled, the same MacOS rule cross-matches Linux telemetry —
// documents the pre-fix behavior and the escape hatch.
func TestRuleEngine_PlatformGate_Disabled_AllowsCrossMatch(t *testing.T) {
	const content = `
title: File and Directory Discovery - MacOS
level: low
detection:
  selection:
    Image|endswith: /ls
  condition: selection
`
	rule := &DetectionRule{
		ID: "macos-disc", Name: "macos", Type: "sigma",
		Enabled: true, Severity: 30, Platform: []string{"macos"}, Content: content,
	}
	e := NewRuleEngine()
	e.SetPlatformGate(false)
	e.LoadRules([]*DetectionRule{rule})

	linuxEvt := map[string]interface{}{
		"type": "process", "agent_id": "host-linux", "platform": "linux",
		"imagePath": "/usr/bin/ls",
	}
	if m, err := e.Evaluate(context.Background(), linuxEvt); err != nil {
		t.Fatalf("Evaluate: %v", err)
	} else if !hasRule(m, "macos-disc") {
		t.Fatalf("with gate off the MacOS rule should cross-match Linux, but did not")
	}
}
