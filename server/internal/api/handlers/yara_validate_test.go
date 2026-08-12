package handlers

import (
	"testing"
)

func TestValidateYARARequest_EmptyName_ReturnsError(t *testing.T) {
	req := &yaraRequest{Name: "", Content: "rule test {}"}
	if got := validateYARARequest(req); got == "" {
		t.Error("empty name should return an error message")
	}
}

func TestValidateYARARequest_WhitespaceName_ReturnsError(t *testing.T) {
	req := &yaraRequest{Name: "   ", Content: "rule test {}"}
	if got := validateYARARequest(req); got == "" {
		t.Error("whitespace-only name should return an error message")
	}
}

func TestValidateYARARequest_EmptyContent_ReturnsError(t *testing.T) {
	req := &yaraRequest{Name: "my-rule", Content: ""}
	if got := validateYARARequest(req); got == "" {
		t.Error("empty content should return an error message")
	}
}

func TestValidateYARARequest_InvalidSeverity_ReturnsError(t *testing.T) {
	req := &yaraRequest{Name: "r", Content: "c", Severity: "unknown"}
	if got := validateYARARequest(req); got == "" {
		t.Error("invalid severity should return an error message")
	}
}

func TestValidateYARARequest_ValidSeverities_NoError(t *testing.T) {
	for _, sev := range []string{"low", "medium", "high", "critical"} {
		req := &yaraRequest{Name: "r", Content: "c", Severity: sev}
		if got := validateYARARequest(req); got != "" {
			t.Errorf("severity %q should be valid, got error: %s", sev, got)
		}
	}
}

func TestValidateYARARequest_EmptySeverity_DefaultsToMedium(t *testing.T) {
	req := &yaraRequest{Name: "r", Content: "c", Severity: ""}
	got := validateYARARequest(req)
	if got != "" {
		t.Errorf("empty severity should be valid (defaults to medium), got: %s", got)
	}
	if req.Severity != "medium" {
		t.Errorf("empty severity should be set to 'medium', got %q", req.Severity)
	}
}

func TestValidateYARARequest_ValidRequest_ReturnsEmpty(t *testing.T) {
	req := &yaraRequest{Name: "detect-miner", Content: "rule miner { strings: $a = /xmrig/ condition: $a }", Severity: "high"}
	if got := validateYARARequest(req); got != "" {
		t.Errorf("valid request should return \"\", got %q", got)
	}
}
