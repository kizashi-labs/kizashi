package investigation

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// baseAlert returns a minimal Alert suitable for use in tests.
func baseAlert() Alert {
	return Alert{
		ID:          "alert-001",
		AgentID:     "agent-abc",
		Hostname:    "workstation-01",
		OS:          "linux",
		Severity:    8,
		Title:       "Suspicious PowerShell Execution",
		Description: "PowerShell launched with encoded command",
		MITRETech:   "T1059.001",
		RuleName:    "ps_encoded_command",
		CreatedAt:   time.Date(2026, 3, 20, 12, 0, 0, 0, time.UTC),
	}
}

func TestBuildPrompt_ContainsAlertTitle(t *testing.T) {
	alert := baseAlert()
	prompt := buildPrompt(alert, nil)

	if !strings.Contains(prompt, alert.Title) {
		t.Errorf("expected prompt to contain alert title %q, but it did not\nprompt:\n%s", alert.Title, prompt)
	}
}

func TestBuildPrompt_ContainsSeverity(t *testing.T) {
	alert := baseAlert()
	prompt := buildPrompt(alert, nil)

	// Severity is formatted as "8 / 10" in the prompt.
	want := "8 / 10"
	if !strings.Contains(prompt, want) {
		t.Errorf("expected prompt to contain %q, but it did not\nprompt:\n%s", want, prompt)
	}
}

func TestBuildPrompt_WithNoEvents(t *testing.T) {
	alert := baseAlert()
	prompt := buildPrompt(alert, []Event{})

	if prompt == "" {
		t.Fatal("expected a non-empty prompt even with no events")
	}

	// The no-events message should appear.
	want := "No events found in the 10-minute window before the alert."
	if !strings.Contains(prompt, want) {
		t.Errorf("expected prompt to contain no-events message %q\nprompt:\n%s", want, prompt)
	}

	// Essential sections must still be present.
	for _, section := range []string{"## Alert Details", "## Affected Endpoint", "## Instructions"} {
		if !strings.Contains(prompt, section) {
			t.Errorf("expected prompt to contain section %q\nprompt:\n%s", section, prompt)
		}
	}
}

func TestBuildPrompt_WithProcessEvents(t *testing.T) {
	alert := baseAlert()

	rawProcess, _ := json.Marshal(map[string]interface{}{
		"image":   "/usr/bin/python3",
		"cmdline": "python3 -c 'import socket'",
		"pid":     "1234",
		"user":    "root",
	})
	events := []Event{
		{
			EventType: "process",
			RawData:   json.RawMessage(rawProcess),
			Timestamp: alert.CreatedAt.Add(-2 * time.Minute),
		},
	}

	prompt := buildPrompt(alert, events)

	// The process section heading should appear.
	if !strings.Contains(prompt, "process") {
		t.Errorf("expected prompt to contain 'process' section\nprompt:\n%s", prompt)
	}

	// The image path extracted from raw data should be present.
	if !strings.Contains(prompt, "/usr/bin/python3") {
		t.Errorf("expected prompt to contain process image '/usr/bin/python3'\nprompt:\n%s", prompt)
	}
}

func TestBuildPrompt_WithNetworkEvents(t *testing.T) {
	alert := baseAlert()

	rawNet, _ := json.Marshal(map[string]interface{}{
		"dst_ip":       "203.0.113.42",
		"dst_port":     "4444",
		"protocol":     "tcp",
		"process_name": "nc",
	})
	events := []Event{
		{
			EventType: "network",
			RawData:   json.RawMessage(rawNet),
			Timestamp: alert.CreatedAt.Add(-5 * time.Minute),
		},
	}

	prompt := buildPrompt(alert, events)

	// The network destination should appear in the prompt.
	if !strings.Contains(prompt, "203.0.113.42") {
		t.Errorf("expected prompt to contain destination IP '203.0.113.42'\nprompt:\n%s", prompt)
	}

	// The process name associated with the network event should appear.
	if !strings.Contains(prompt, "nc") {
		t.Errorf("expected prompt to contain process name 'nc'\nprompt:\n%s", prompt)
	}
}
