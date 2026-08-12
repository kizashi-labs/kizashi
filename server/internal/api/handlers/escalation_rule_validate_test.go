package handlers

import "testing"

// ─── validateEscalationRuleRequest ───────────────────────────────────────────

func TestValidateEscalationRule_Valid(t *testing.T) {
	req := &escalationRuleRequest{
		Name:           "High Severity Escalation",
		SeverityMin:    7,
		UnresolvedMins: 30,
		EscalateTo:     "oncall@example.com",
	}
	if msg := validateEscalationRuleRequest(req); msg != "" {
		t.Errorf("有効なリクエスト: エラーなしを期待、got %q", msg)
	}
}

func TestValidateEscalationRule_EmptyName(t *testing.T) {
	req := &escalationRuleRequest{SeverityMin: 5, UnresolvedMins: 15, EscalateTo: "team@example.com"}
	if validateEscalationRuleRequest(req) == "" {
		t.Error("name が空のとき エラーが返るべきです")
	}
}

func TestValidateEscalationRule_SpaceOnlyName(t *testing.T) {
	req := &escalationRuleRequest{Name: "   ", SeverityMin: 5, UnresolvedMins: 15, EscalateTo: "team@example.com"}
	if validateEscalationRuleRequest(req) == "" {
		t.Error("name がスペースのみ: エラーが返るべきです")
	}
}

func TestValidateEscalationRule_EmptyEscalateTo(t *testing.T) {
	req := &escalationRuleRequest{Name: "rule", SeverityMin: 5, UnresolvedMins: 15, EscalateTo: ""}
	if validateEscalationRuleRequest(req) == "" {
		t.Error("escalate_to が空のとき エラーが返るべきです")
	}
}

func TestValidateEscalationRule_SeverityMinZero(t *testing.T) {
	req := &escalationRuleRequest{Name: "rule", SeverityMin: 0, UnresolvedMins: 15, EscalateTo: "team@example.com"}
	if validateEscalationRuleRequest(req) == "" {
		t.Error("severity_min=0: エラーが返るべきです (1〜10 の範囲外)")
	}
}

func TestValidateEscalationRule_SeverityMinTooHigh(t *testing.T) {
	req := &escalationRuleRequest{Name: "rule", SeverityMin: 11, UnresolvedMins: 15, EscalateTo: "team@example.com"}
	if validateEscalationRuleRequest(req) == "" {
		t.Error("severity_min=11: エラーが返るべきです (1〜10 の範囲外)")
	}
}

func TestValidateEscalationRule_SeverityBoundaryValues(t *testing.T) {
	for _, sev := range []int16{1, 5, 10} {
		req := &escalationRuleRequest{Name: "rule", SeverityMin: sev, UnresolvedMins: 15, EscalateTo: "team@example.com"}
		if msg := validateEscalationRuleRequest(req); msg != "" {
			t.Errorf("severity_min=%d は有効なはず、got error: %q", sev, msg)
		}
	}
}

func TestValidateEscalationRule_UnresolvedMinsZero(t *testing.T) {
	req := &escalationRuleRequest{Name: "rule", SeverityMin: 5, UnresolvedMins: 0, EscalateTo: "team@example.com"}
	if validateEscalationRuleRequest(req) == "" {
		t.Error("unresolved_mins=0: エラーが返るべきです (1以上)")
	}
}

func TestValidateEscalationRule_UnresolvedMinsNegative(t *testing.T) {
	req := &escalationRuleRequest{Name: "rule", SeverityMin: 5, UnresolvedMins: -1, EscalateTo: "team@example.com"}
	if validateEscalationRuleRequest(req) == "" {
		t.Error("unresolved_mins=-1: エラーが返るべきです")
	}
}

func TestValidateEscalationRule_UnresolvedMinsOne_Valid(t *testing.T) {
	req := &escalationRuleRequest{Name: "rule", SeverityMin: 1, UnresolvedMins: 1, EscalateTo: "team@example.com"}
	if msg := validateEscalationRuleRequest(req); msg != "" {
		t.Errorf("unresolved_mins=1 は有効なはず、got error: %q", msg)
	}
}
