package handlers

import "testing"

// ─── validateProcessBlockRequest ─────────────────────────────────────────────

func TestValidateProcessBlockRequest_Valid(t *testing.T) {
	req := &processBlockRuleRequest{
		Name:        "Block Mimikatz",
		ProcessName: "mimikatz.exe",
	}
	if got := validateProcessBlockRequest(req); got != "" {
		t.Errorf("validateProcessBlockRequest(valid) = %q, want empty", got)
	}
}

func TestValidateProcessBlockRequest_EmptyName_ReturnsError(t *testing.T) {
	req := &processBlockRuleRequest{ProcessName: "evil.exe"}
	if got := validateProcessBlockRequest(req); got == "" {
		t.Error("validateProcessBlockRequest(no name): expected error")
	}
}

func TestValidateProcessBlockRequest_EmptyProcessName_ReturnsError(t *testing.T) {
	req := &processBlockRuleRequest{Name: "test rule"}
	if got := validateProcessBlockRequest(req); got == "" {
		t.Error("validateProcessBlockRequest(no process_name): expected error")
	}
}

func TestValidateProcessBlockRequest_DefaultRuleType_IsDeny(t *testing.T) {
	req := &processBlockRuleRequest{
		Name:        "rule",
		ProcessName: "proc.exe",
	}
	validateProcessBlockRequest(req)
	if req.RuleType != "deny" {
		t.Errorf("validateProcessBlockRequest: default rule_type = %q, want 'deny'", req.RuleType)
	}
}

func TestValidateProcessBlockRequest_InvalidRuleType_ReturnsError(t *testing.T) {
	req := &processBlockRuleRequest{
		Name:        "rule",
		ProcessName: "proc.exe",
		RuleType:    "invalid",
	}
	if got := validateProcessBlockRequest(req); got == "" {
		t.Error("validateProcessBlockRequest(invalid rule_type): expected error")
	}
}

func TestValidateProcessBlockRequest_DefaultScope_IsAll(t *testing.T) {
	req := &processBlockRuleRequest{
		Name:        "rule",
		ProcessName: "proc.exe",
	}
	validateProcessBlockRequest(req)
	if req.Scope != "all" {
		t.Errorf("validateProcessBlockRequest: default scope = %q, want 'all'", req.Scope)
	}
}

func TestValidateProcessBlockRequest_NonAllScope_RequiresScopeID(t *testing.T) {
	req := &processBlockRuleRequest{
		Name:        "rule",
		ProcessName: "proc.exe",
		Scope:       "agent",
	}
	if got := validateProcessBlockRequest(req); got == "" {
		t.Error("validateProcessBlockRequest(scope=agent, no scope_id): expected error")
	}
}
