package handlers

import "testing"

// ─── validateFIMRequest ──────────────────────────────────────────────────────

func TestValidateFIMRequest_Valid(t *testing.T) {
	req := &fimRuleRequest{
		Name:     "etc passwd",
		Path:     "/etc/passwd",
		Severity: "high",
	}
	if msg := validateFIMRequest(req); msg != "" {
		t.Errorf("有効なリクエスト: エラーなしを期待、got %q", msg)
	}
}

func TestValidateFIMRequest_EmptyName_ReturnsError(t *testing.T) {
	req := &fimRuleRequest{Path: "/etc", Severity: "low"}
	msg := validateFIMRequest(req)
	if msg == "" {
		t.Error("name が空のとき エラーが返るべきです")
	}
}

func TestValidateFIMRequest_SpaceOnlyName_ReturnsError(t *testing.T) {
	req := &fimRuleRequest{Name: "   ", Path: "/etc", Severity: "low"}
	msg := validateFIMRequest(req)
	if msg == "" {
		t.Error("name がスペースのみのとき エラーが返るべきです")
	}
}

func TestValidateFIMRequest_EmptyPath_ReturnsError(t *testing.T) {
	req := &fimRuleRequest{Name: "rule", Severity: "low"}
	msg := validateFIMRequest(req)
	if msg == "" {
		t.Error("path が空のとき エラーが返るべきです")
	}
}

func TestValidateFIMRequest_InvalidSeverity_ReturnsError(t *testing.T) {
	req := &fimRuleRequest{Name: "rule", Path: "/etc", Severity: "unknown"}
	msg := validateFIMRequest(req)
	if msg == "" {
		t.Error("無効な severity のとき エラーが返るべきです")
	}
}

func TestValidateFIMRequest_EmptySeverity_DefaultsToHigh(t *testing.T) {
	req := &fimRuleRequest{Name: "rule", Path: "/etc", Severity: ""}
	msg := validateFIMRequest(req)
	if msg != "" {
		t.Errorf("severity 未指定はデフォルト 'high' になるはず、got error: %q", msg)
	}
	if req.Severity != "high" {
		t.Errorf("severity がデフォルト high にならない、got %q", req.Severity)
	}
}

func TestValidateFIMRequest_ValidSeverities(t *testing.T) {
	for _, sev := range []string{"low", "medium", "high", "critical"} {
		req := &fimRuleRequest{Name: "rule", Path: "/etc", Severity: sev}
		if msg := validateFIMRequest(req); msg != "" {
			t.Errorf("severity %q は有効なはず、got error: %q", sev, msg)
		}
	}
}

// ─── validFIMSeverities ──────────────────────────────────────────────────────

func TestValidFIMSeverities_ContainsAllLevels(t *testing.T) {
	for _, s := range []string{"low", "medium", "high", "critical"} {
		if _, ok := validFIMSeverities[s]; !ok {
			t.Errorf("validFIMSeverities に %q が含まれていません", s)
		}
	}
}

func TestValidFIMSeverities_ExactlyFourEntries(t *testing.T) {
	if len(validFIMSeverities) != 4 {
		t.Errorf("validFIMSeverities は4エントリのはず、got %d", len(validFIMSeverities))
	}
}
