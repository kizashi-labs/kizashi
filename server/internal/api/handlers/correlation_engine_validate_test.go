package handlers

import "testing"

// ─── validateCERequest ────────────────────────────────────────────────────────

func TestValidateCERequest_Valid(t *testing.T) {
	req := &correlationEngineRuleRequest{
		Name:             "Test Rule",
		TriggerEventType: "process_create",
		FollowEventType:  "network_connect",
		AlertTitle:       "Suspicious Activity",
	}
	if got := validateCERequest(req); got != "" {
		t.Errorf("validateCERequest(valid) = %q, want empty", got)
	}
}

func TestValidateCERequest_EmptyName_ReturnsError(t *testing.T) {
	req := &correlationEngineRuleRequest{
		TriggerEventType: "process_create",
		FollowEventType:  "network_connect",
		AlertTitle:       "Alert",
	}
	if got := validateCERequest(req); got == "" {
		t.Error("validateCERequest(no name): expected error")
	}
}

func TestValidateCERequest_EmptyTriggerEventType_ReturnsError(t *testing.T) {
	req := &correlationEngineRuleRequest{
		Name:            "Rule",
		FollowEventType: "network_connect",
		AlertTitle:      "Alert",
	}
	if got := validateCERequest(req); got == "" {
		t.Error("validateCERequest(no trigger_event_type): expected error")
	}
}

func TestValidateCERequest_EmptyFollowEventType_ReturnsError(t *testing.T) {
	req := &correlationEngineRuleRequest{
		Name:             "Rule",
		TriggerEventType: "process_create",
		AlertTitle:       "Alert",
	}
	if got := validateCERequest(req); got == "" {
		t.Error("validateCERequest(no follow_event_type): expected error")
	}
}

func TestValidateCERequest_EmptyAlertTitle_ReturnsError(t *testing.T) {
	req := &correlationEngineRuleRequest{
		Name:             "Rule",
		TriggerEventType: "process_create",
		FollowEventType:  "network_connect",
	}
	if got := validateCERequest(req); got == "" {
		t.Error("validateCERequest(no alert_title): expected error")
	}
}

func TestValidateCERequest_DefaultTimeWindow_Is300(t *testing.T) {
	req := &correlationEngineRuleRequest{
		Name:             "Rule",
		TriggerEventType: "process_create",
		FollowEventType:  "network_connect",
		AlertTitle:       "Alert",
	}
	validateCERequest(req)
	if req.TimeWindowSeconds != 300 {
		t.Errorf("validateCERequest: default time_window_seconds = %d, want 300", req.TimeWindowSeconds)
	}
}

func TestValidateCERequest_DefaultAlertSeverity_Is7(t *testing.T) {
	req := &correlationEngineRuleRequest{
		Name:             "Rule",
		TriggerEventType: "process_create",
		FollowEventType:  "network_connect",
		AlertTitle:       "Alert",
	}
	validateCERequest(req)
	if req.AlertSeverity != 7 {
		t.Errorf("validateCERequest: default alert_severity = %d, want 7", req.AlertSeverity)
	}
}
