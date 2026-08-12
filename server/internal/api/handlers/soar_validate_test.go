package handlers

import (
	"encoding/json"
	"testing"
)

// ─── maskConfig ───────────────────────────────────────────────────────────────

func TestMaskConfig_MasksSensitiveKeys(t *testing.T) {
	raw := json.RawMessage(`{"api_token":"secret123","endpoint":"https://example.com"}`)
	got := maskConfig(raw)
	if got["api_token"] != "***" {
		t.Errorf("maskConfig: api_token = %v, want '***'", got["api_token"])
	}
	if got["endpoint"] != "https://example.com" {
		t.Errorf("maskConfig: endpoint should be unchanged, got %v", got["endpoint"])
	}
}

func TestMaskConfig_MasksPassword(t *testing.T) {
	raw := json.RawMessage(`{"password":"mypass","url":"https://example.com"}`)
	got := maskConfig(raw)
	if got["password"] != "***" {
		t.Errorf("maskConfig: password = %v, want '***'", got["password"])
	}
}

func TestMaskConfig_MasksToken(t *testing.T) {
	raw := json.RawMessage(`{"token":"tok123"}`)
	got := maskConfig(raw)
	if got["token"] != "***" {
		t.Errorf("maskConfig: token = %v, want '***'", got["token"])
	}
}

func TestMaskConfig_InvalidJSON_ReturnsEmpty(t *testing.T) {
	got := maskConfig(json.RawMessage("not json"))
	if len(got) != 0 {
		t.Errorf("maskConfig(invalid): want empty map, got %v", got)
	}
}

func TestMaskConfig_NonSensitiveKeys_Unchanged(t *testing.T) {
	raw := json.RawMessage(`{"name":"jira","type":"ticket"}`)
	got := maskConfig(raw)
	if got["name"] != "jira" || got["type"] != "ticket" {
		t.Errorf("maskConfig: non-sensitive keys changed: %v", got)
	}
}

// ─── severityToPriority ───────────────────────────────────────────────────────

func TestSeverityToPriority_Critical(t *testing.T) {
	for _, v := range []int{9, 10} {
		if got := severityToPriority(v); got != "critical" {
			t.Errorf("severityToPriority(%d) = %q, want 'critical'", v, got)
		}
	}
}

func TestSeverityToPriority_High(t *testing.T) {
	for _, v := range []int{7, 8} {
		if got := severityToPriority(v); got != "high" {
			t.Errorf("severityToPriority(%d) = %q, want 'high'", v, got)
		}
	}
}

func TestSeverityToPriority_Medium(t *testing.T) {
	for _, v := range []int{4, 5, 6} {
		if got := severityToPriority(v); got != "medium" {
			t.Errorf("severityToPriority(%d) = %q, want 'medium'", v, got)
		}
	}
}

func TestSeverityToPriority_Low(t *testing.T) {
	for _, v := range []int{0, 1, 3} {
		if got := severityToPriority(v); got != "low" {
			t.Errorf("severityToPriority(%d) = %q, want 'low'", v, got)
		}
	}
}
