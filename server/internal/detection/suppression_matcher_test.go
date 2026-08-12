package detection

import (
	"context"
	"testing"
	"time"
)

// fakeSuppLoader is a test SuppressionLoader returning a fixed rule set.
type fakeSuppLoader struct {
	rules []SuppressionRule
	err   error
}

func (f *fakeSuppLoader) ListActiveSuppressions(context.Context) ([]SuppressionRule, error) {
	return f.rules, f.err
}

func newMatcher(t *testing.T, rules ...SuppressionRule) *SuppressionMatcher {
	t.Helper()
	m := NewSuppressionMatcher(&fakeSuppLoader{rules: rules})
	m.RefreshNow(context.Background())
	if m.Count() != len(rules) {
		t.Fatalf("expected %d rules loaded, got %d", len(rules), m.Count())
	}
	return m
}

// TestSuppression_EmptyRuleNeverSuppresses guards against a real past bug where
// an empty conditions row acted as a catch-all and dropped every alert.
func TestSuppression_EmptyRuleNeverSuppresses(t *testing.T) {
	m := newMatcher(t, SuppressionRule{ID: "r1", Name: "empty"})
	alert := &StoredAlert{RuleName: "anything", Severity: 9}
	if supp, _, _ := m.IsSuppressed(alert); supp {
		t.Error("an all-empty suppression rule must NOT suppress alerts")
	}
}

func TestSuppression_RuleName(t *testing.T) {
	m := newMatcher(t, SuppressionRule{ID: "r1", Name: "byname", RuleName: "powershell"})
	cases := []struct {
		ruleName string
		want     bool
	}{
		{"Suspicious PowerShell Exec", true}, // substring, case-insensitive
		{"POWERSHELL download", true},
		{"cmd.exe spawn", false},
	}
	for _, tc := range cases {
		supp, name, id := m.IsSuppressed(&StoredAlert{RuleName: tc.ruleName})
		if supp != tc.want {
			t.Errorf("RuleName %q: got %v, want %v", tc.ruleName, supp, tc.want)
		}
		if tc.want && (name != "byname" || id != "r1") {
			t.Errorf("RuleName %q: expected name/id byname/r1, got %s/%s", tc.ruleName, name, id)
		}
	}
}

func TestSuppression_Hostname(t *testing.T) {
	m := newMatcher(t, SuppressionRule{ID: "r1", Name: "host", Hostname: "test-"})
	if supp, _, _ := m.IsSuppressed(&StoredAlert{Hostname: "TEST-WIN01"}); !supp {
		t.Error("expected hostname substring (case-insensitive) to suppress")
	}
	if supp, _, _ := m.IsSuppressed(&StoredAlert{Hostname: "prod-win01"}); supp {
		t.Error("expected non-matching hostname not to suppress")
	}
}

func TestSuppression_SeverityMax(t *testing.T) {
	m := newMatcher(t, SuppressionRule{ID: "r1", Name: "sev", SeverityMax: 4})
	if supp, _, _ := m.IsSuppressed(&StoredAlert{Severity: 3}); !supp {
		t.Error("severity 3 <= max 4 should be suppressed")
	}
	if supp, _, _ := m.IsSuppressed(&StoredAlert{Severity: 4}); !supp {
		t.Error("severity 4 == max 4 should be suppressed")
	}
	if supp, _, _ := m.IsSuppressed(&StoredAlert{Severity: 7}); supp {
		t.Error("severity 7 > max 4 should NOT be suppressed")
	}
}

func TestSuppression_MITRETechniquePrefix(t *testing.T) {
	m := newMatcher(t, SuppressionRule{ID: "r1", Name: "mitre", MITRETechnique: "T1059"})
	if supp, _, _ := m.IsSuppressed(&StoredAlert{MITRETech: "T1059.001"}); !supp {
		t.Error("T1059.001 should match prefix T1059 (case-insensitive)")
	}
	if supp, _, _ := m.IsSuppressed(&StoredAlert{MITRETech: "t1059"}); !supp {
		t.Error("exact technique (lowercased) should match")
	}
	if supp, _, _ := m.IsSuppressed(&StoredAlert{MITRETech: "T1003"}); supp {
		t.Error("T1003 should not match prefix T1059")
	}
}

func TestSuppression_AgentIDExact(t *testing.T) {
	m := newMatcher(t, SuppressionRule{ID: "r1", Name: "agent", AgentID: "agent-123"})
	if supp, _, _ := m.IsSuppressed(&StoredAlert{AgentID: "agent-123"}); !supp {
		t.Error("exact agent id should suppress")
	}
	if supp, _, _ := m.IsSuppressed(&StoredAlert{AgentID: "agent-123-x"}); supp {
		t.Error("agent id is exact match — partial must not suppress")
	}
}

// TestSuppression_MultipleConditionsAreAND verifies all populated conditions
// must match for a rule to suppress.
func TestSuppression_MultipleConditionsAreAND(t *testing.T) {
	m := newMatcher(t, SuppressionRule{
		ID: "r1", Name: "combo",
		RuleName: "powershell", Hostname: "test-", SeverityMax: 5,
	})
	full := &StoredAlert{RuleName: "PowerShell exec", Hostname: "test-01", Severity: 3}
	if supp, _, _ := m.IsSuppressed(full); !supp {
		t.Error("alert satisfying all conditions should be suppressed")
	}
	// Hostname mismatch breaks the AND.
	partial := &StoredAlert{RuleName: "PowerShell exec", Hostname: "prod-01", Severity: 3}
	if supp, _, _ := m.IsSuppressed(partial); supp {
		t.Error("one failing condition must prevent suppression (AND semantics)")
	}
	// Severity above max breaks the AND.
	loud := &StoredAlert{RuleName: "PowerShell exec", Hostname: "test-01", Severity: 9}
	if supp, _, _ := m.IsSuppressed(loud); supp {
		t.Error("severity above max must prevent suppression")
	}
}

func TestSuppression_ExpiredRuleSkipped(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)
	m := newMatcher(t,
		SuppressionRule{ID: "exp", Name: "expired", RuleName: "powershell", ExpiresAt: &past},
		SuppressionRule{ID: "live", Name: "active", RuleName: "cmd", ExpiresAt: &future},
	)
	// Matches the expired rule's condition but it must be skipped.
	if supp, _, _ := m.IsSuppressed(&StoredAlert{RuleName: "PowerShell exec"}); supp {
		t.Error("expired suppression rule must be skipped")
	}
	// Matches the still-active rule.
	if supp, name, _ := m.IsSuppressed(&StoredAlert{RuleName: "cmd spawn"}); !supp || name != "active" {
		t.Errorf("active rule should suppress, got supp=%v name=%s", supp, name)
	}
}

func TestSuppression_NoRulesNoSuppression(t *testing.T) {
	m := newMatcher(t)
	if supp, _, _ := m.IsSuppressed(&StoredAlert{RuleName: "x", Severity: 1}); supp {
		t.Error("with no rules loaded, nothing should be suppressed")
	}
}
