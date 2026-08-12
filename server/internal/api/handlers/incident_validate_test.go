package handlers

import "testing"

// ─── isValidIncidentStatus ────────────────────────────────────────────────

func TestIsValidIncidentStatus_Valid(t *testing.T) {
	for _, s := range []string{"open", "investigating", "resolved", "closed"} {
		if !isValidIncidentStatus(s) {
			t.Errorf("ステータス %q は有効なはず", s)
		}
	}
}

func TestIsValidIncidentStatus_Invalid(t *testing.T) {
	for _, s := range []string{"", "unknown", "pending", "OPEN", "Resolved"} {
		if isValidIncidentStatus(s) {
			t.Errorf("ステータス %q は無効なはず", s)
		}
	}
}

func TestIsValidIncidentStatus_CaseSensitive(t *testing.T) {
	if isValidIncidentStatus("Open") {
		t.Error("'Open' (大文字) は無効であるべきです")
	}
}

// ─── clampIncidentSeverity ────────────────────────────────────────────────

func TestClampIncidentSeverity_ValidRange(t *testing.T) {
	for v := 1; v <= 10; v++ {
		got := clampIncidentSeverity(v)
		if got != v {
			t.Errorf("severity=%d: clamp後も同値のはず、got %d", v, got)
		}
	}
}

func TestClampIncidentSeverity_Zero(t *testing.T) {
	if got := clampIncidentSeverity(0); got != 7 {
		t.Errorf("0 はデフォルト7になるはず、got %d", got)
	}
}

func TestClampIncidentSeverity_Negative(t *testing.T) {
	if got := clampIncidentSeverity(-5); got != 7 {
		t.Errorf("-5 はデフォルト7になるはず、got %d", got)
	}
}

func TestClampIncidentSeverity_TooHigh(t *testing.T) {
	if got := clampIncidentSeverity(11); got != 7 {
		t.Errorf("11 はデフォルト7になるはず、got %d", got)
	}
}

func TestClampIncidentSeverity_Boundary(t *testing.T) {
	if got := clampIncidentSeverity(1); got != 1 {
		t.Errorf("下限1: got %d", got)
	}
	if got := clampIncidentSeverity(10); got != 10 {
		t.Errorf("上限10: got %d", got)
	}
}

// ─── defaultIncidentStatus ────────────────────────────────────────────────

func TestDefaultIncidentStatus_Empty(t *testing.T) {
	if got := defaultIncidentStatus(""); got != "open" {
		t.Errorf("空文字は 'open' になるはず、got %q", got)
	}
}

func TestDefaultIncidentStatus_NonEmpty(t *testing.T) {
	for _, s := range []string{"investigating", "resolved", "closed", "custom"} {
		if got := defaultIncidentStatus(s); got != s {
			t.Errorf("非空文字 %q はそのまま返るはず、got %q", s, got)
		}
	}
}

// ─── validIncidentStatuses map ────────────────────────────────────────────

func TestValidIncidentStatusesMap_HasAllStatuses(t *testing.T) {
	required := []string{"open", "investigating", "resolved", "closed"}
	for _, s := range required {
		if !validIncidentStatuses[s] {
			t.Errorf("validIncidentStatuses に %q が含まれていません", s)
		}
	}
}
