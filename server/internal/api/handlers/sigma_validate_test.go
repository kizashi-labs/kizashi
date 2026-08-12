package handlers

import "testing"

// ─── sigmaLevelToSeverityInt ─────────────────────────────────────────────────

func TestSigmaLevelToSeverityInt_Critical(t *testing.T) {
	if got := sigmaLevelToSeverityInt("critical"); got != 10 {
		t.Errorf("sigmaLevelToSeverityInt(critical) = %d, want 10", got)
	}
}

func TestSigmaLevelToSeverityInt_High(t *testing.T) {
	if got := sigmaLevelToSeverityInt("high"); got != 8 {
		t.Errorf("sigmaLevelToSeverityInt(high) = %d, want 8", got)
	}
}

func TestSigmaLevelToSeverityInt_Medium(t *testing.T) {
	if got := sigmaLevelToSeverityInt("medium"); got != 5 {
		t.Errorf("sigmaLevelToSeverityInt(medium) = %d, want 5", got)
	}
}

func TestSigmaLevelToSeverityInt_Low(t *testing.T) {
	if got := sigmaLevelToSeverityInt("low"); got != 3 {
		t.Errorf("sigmaLevelToSeverityInt(low) = %d, want 3", got)
	}
}

func TestSigmaLevelToSeverityInt_Unknown_Default(t *testing.T) {
	if got := sigmaLevelToSeverityInt("informational"); got != 2 {
		t.Errorf("sigmaLevelToSeverityInt(informational) = %d, want 2", got)
	}
}

func TestSigmaLevelToSeverityInt_CaseInsensitive(t *testing.T) {
	if got := sigmaLevelToSeverityInt("HIGH"); got != 8 {
		t.Errorf("sigmaLevelToSeverityInt(HIGH) = %d, want 8", got)
	}
}

// ─── sigmaLevelToSeverityText ─────────────────────────────────────────────────

func TestSigmaLevelToSeverityText_Critical(t *testing.T) {
	if got := sigmaLevelToSeverityText("critical"); got != "critical" {
		t.Errorf("sigmaLevelToSeverityText(critical) = %q, want 'critical'", got)
	}
}

func TestSigmaLevelToSeverityText_High(t *testing.T) {
	if got := sigmaLevelToSeverityText("high"); got != "high" {
		t.Errorf("sigmaLevelToSeverityText(high) = %q, want 'high'", got)
	}
}

func TestSigmaLevelToSeverityText_Medium(t *testing.T) {
	if got := sigmaLevelToSeverityText("medium"); got != "medium" {
		t.Errorf("sigmaLevelToSeverityText(medium) = %q, want 'medium'", got)
	}
}

func TestSigmaLevelToSeverityText_LowDefault(t *testing.T) {
	if got := sigmaLevelToSeverityText("low"); got != "low" {
		t.Errorf("sigmaLevelToSeverityText(low) = %q, want 'low'", got)
	}
}

func TestSigmaLevelToSeverityText_Unknown_ReturnsLow(t *testing.T) {
	if got := sigmaLevelToSeverityText("informational"); got != "low" {
		t.Errorf("sigmaLevelToSeverityText(informational) = %q, want 'low'", got)
	}
}
