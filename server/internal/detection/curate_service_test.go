package detection

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestRuleCategory(t *testing.T) {
	cases := []struct{ yaml, want string }{
		{"logsource:\n  category: process_creation\n", "process_creation"},
		{"logsource:\n  service: sysmon\n", "service:sysmon"},
		{"logsource:\n  product: windows\n", "product:windows"},
		{"title: x\n", "(none)"},
		{"[unclosed", "(unparseable)"}, // malformed flow sequence → yaml parse error
	}
	for _, c := range cases {
		if got := RuleCategory(c.yaml); got != c.want {
			t.Errorf("RuleCategory(%q) = %q, want %q", c.yaml, got, c.want)
		}
	}
}

// ── fake CurateDB (minimal pgx.Rows / Exec) ────────────────────────────────

type fakeRows struct {
	data [][]any
	i    int
}

func (r *fakeRows) Next() bool {
	if r.i < len(r.data) {
		r.i++
		return true
	}
	return false
}
func (r *fakeRows) Scan(dest ...any) error {
	row := r.data[r.i-1]
	for k := range dest {
		switch d := dest[k].(type) {
		case *string:
			*d = row[k].(string)
		case *bool:
			*d = row[k].(bool)
		case *int:
			*d = row[k].(int)
		}
	}
	return nil
}
func (r *fakeRows) Close()                                       {}
func (r *fakeRows) Err() error                                   { return nil }
func (r *fakeRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (r *fakeRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *fakeRows) Values() ([]any, error)                       { return nil, nil }
func (r *fakeRows) RawValues() [][]byte                          { return nil }
func (r *fakeRows) Conn() *pgx.Conn                              { return nil }

type fakeExec struct {
	sql  string
	args []any
}

type fakeCurateDB struct {
	statusRows     [][]any
	candidateRows  [][]any
	fpRows         [][]any
	inertRows      [][]any
	fieldGapRows   [][]any
	falseGreenRows [][]any
	execs          []fakeExec
}

func (f *fakeCurateDB) Query(_ context.Context, sql string, _ ...any) (pgx.Rows, error) {
	switch {
	case strings.Contains(sql, "COALESCE(curate_state"):
		return &fakeRows{data: f.statusRows}, nil
	case strings.Contains(sql, "HAVING COUNT"):
		return &fakeRows{data: f.fpRows}, nil
	case strings.Contains(sql, "NOT EXISTS"): // InertRules canary
		return &fakeRows{data: f.inertRows}, nil
	// FalseGreenRules first: its "name, content FROM rules WHERE …" query is a
	// superstring of FieldGapReport's "content FROM rules WHERE …", so the more
	// specific match must be tested before the field-gap case swallows it.
	case strings.Contains(sql, "name, content FROM rules"): // FalseGreenRules canary
		return &fakeRows{data: f.falseGreenRows}, nil
	case strings.Contains(sql, "content FROM rules WHERE source='sigmahq' AND enabled=true"): // FieldGapReport
		return &fakeRows{data: f.fieldGapRows}, nil
	case strings.Contains(sql, "curate_state IS NULL OR"):
		return &fakeRows{data: f.candidateRows}, nil
	}
	return &fakeRows{}, nil
}
func (f *fakeCurateDB) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	f.execs = append(f.execs, fakeExec{sql: sql, args: args})
	return pgconn.NewCommandTag("UPDATE 1"), nil
}

type fakePub struct{ subjects []string }

func (p *fakePub) Publish(subject string, _ []byte) error {
	p.subjects = append(p.subjects, subject)
	return nil
}

// TestCurateService_ReconcileQuarantined checks the invariant enforcer issues an
// UPDATE (re-disabling quarantined-but-enabled rules) and fires rules.invalidate.
func TestCurateService_ReconcileQuarantined(t *testing.T) {
	db := &fakeCurateDB{}
	pub := &fakePub{}
	svc := NewCurateService(db, pub)

	n, err := svc.ReconcileQuarantined(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 { // fake Exec returns "UPDATE 1"
		t.Fatalf("reconciled = %d, want 1", n)
	}
	if len(db.execs) != 1 || !strings.Contains(db.execs[0].sql, "curate_state='quarantined'") ||
		!strings.Contains(db.execs[0].sql, "enabled=false") {
		t.Fatalf("expected an UPDATE disabling quarantined rules, got %+v", db.execs)
	}
	if len(pub.subjects) != 1 || pub.subjects[0] != "rules.invalidate" {
		t.Fatalf("expected rules.invalidate publish, got %v", pub.subjects)
	}
}

// TestCurateService_InertRules checks the canary returns the names of curate-enabled
// rules that never fired (the silent-inert signal).
func TestCurateService_InertRules(t *testing.T) {
	db := &fakeCurateDB{inertRows: [][]any{{"Dead Rule A"}, {"Dead Rule B"}}}
	svc := NewCurateService(db, nil)

	names, err := svc.InertRules(context.Background(), 7*24*time.Hour, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 2 || names[0] != "Dead Rule A" || names[1] != "Dead Rule B" {
		t.Fatalf("inert names = %v, want [Dead Rule A, Dead Rule B]", names)
	}
}

// TestCurateService_FieldGapReport checks the field-gap canary aggregates
// enabled-but-inert rules by the missing telemetry field, ranked most-rules-first.
func TestCurateService_FieldGapReport(t *testing.T) {
	// GrantedAccess / CallTrace are Sysmon EID10 fields the telemetry does not emit,
	// so they stay field-unsupported (the PE VERSIONINFO / Initiated fields that were
	// once gaps are now supported — see false-green消化 2026-07-03 — so don't use them).
	sup := ruleYAML("ok", "CommandLine|contains") // field-supported → not inert
	gapA := ruleYAML("gapa", "GrantedAccess")     // unsupported → inert (GrantedAccess)
	gapB := ruleYAML("gapb", "GrantedAccess")     // unsupported → inert (GrantedAccess)
	gapC := ruleYAML("gapc", "CallTrace")         // unsupported → inert (CallTrace)
	db := &fakeCurateDB{fieldGapRows: [][]any{{sup}, {gapA}, {gapB}, {gapC}}}
	svc := NewCurateService(db, nil)

	inert, gaps, err := svc.FieldGapReport(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if inert != 3 {
		t.Fatalf("inert = %d, want 3", inert)
	}
	if len(gaps) == 0 || gaps[0].Field != "GrantedAccess" || gaps[0].Rules != 2 {
		t.Fatalf("top gap = %+v, want GrantedAccess=2 first", gaps)
	}
}

// TestCurateService_FalseGreenRules checks the static field-contract canary flags
// an ENABLED rule that is field-unsupported (a false green) and passes a supported
// one — the regression guard for the enabled set's field contract.
func TestCurateService_FalseGreenRules(t *testing.T) {
	supported := `
title: Supported
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains: '-enc'
  condition: selection`
	falseGreen := `
title: Needs Sysmon EID10
detection:
  selection:
    GrantedAccess: '0x1410'
    CallTrace|contains: 'UNKNOWN'
  condition: selection`
	db := &fakeCurateDB{falseGreenRows: [][]any{
		{"Supported Rule", supported},
		{"False Green Rule", falseGreen},
	}}
	svc := NewCurateService(db, nil)

	names, err := svc.FalseGreenRules(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 1 || names[0] != "False Green Rule" {
		t.Fatalf("false-green names = %v, want [False Green Rule]", names)
	}
}

// TestCurateService_Status checks the four lifecycle buckets are derived from the
// field gate + enabled/quarantine state (not just stored curate_state).
func TestCurateService_Status(t *testing.T) {
	sup := ruleYAML("ok", "CommandLine|contains") // field-supported
	unsup := ruleYAML("inert", "GrantedAccess")   // field-unsupported
	db := &fakeCurateDB{statusRows: [][]any{
		{sup, true, "enabled"},      // → Enabled + Supported
		{sup, false, ""},            // → Deferred + Supported
		{unsup, false, ""},          // → Pending
		{sup, false, "quarantined"}, // → Quarantined
	}}
	svc := NewCurateService(db, nil)
	st, err := svc.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	tot := st.Total
	if tot.Total != 4 || tot.Enabled != 1 || tot.Deferred != 1 || tot.Pending != 1 || tot.Quarantined != 1 || tot.Supported != 2 {
		t.Fatalf("totals = %+v, want total=4 enabled=1 deferred=1 pending=1 quarantined=1 supported=2", tot)
	}
}

// TestCurateService_RunRound checks a round enables the field-supported candidates
// (skipping the unsupported one) and fires rules.invalidate.
func TestCurateService_RunRound(t *testing.T) {
	sup := ruleYAML("ok", "CommandLine|contains")
	unsup := ruleYAML("inert", "GrantedAccess")
	db := &fakeCurateDB{candidateRows: [][]any{
		{"a", sup},
		{"b", sup},
		{"c", unsup},
	}}
	pub := &fakePub{}
	svc := NewCurateService(db, pub)

	res, err := svc.RunRound(context.Background(), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.Enabled != 2 || res.Pending != 1 {
		t.Fatalf("round result = %+v, want enabled=2 pending=1", res)
	}

	// An enable UPDATE must have run with the two supported IDs.
	var enabledIDs []string
	for _, e := range db.execs {
		if strings.Contains(e.sql, "SET enabled=true") {
			if ids, ok := e.args[0].([]string); ok {
				enabledIDs = ids
			}
		}
	}
	if len(enabledIDs) != 2 {
		t.Fatalf("enable UPDATE ids = %v, want 2 ids", enabledIDs)
	}
	if len(pub.subjects) != 1 || pub.subjects[0] != "rules.invalidate" {
		t.Fatalf("published = %v, want [rules.invalidate]", pub.subjects)
	}
}

// TestCurateService_MonitorFP quarantines a noisy curate-enabled rule and signals reload.
func TestCurateService_MonitorFP(t *testing.T) {
	db := &fakeCurateDB{fpRows: [][]any{{"noisy-id", 120}}}
	pub := &fakePub{}
	svc := NewCurateService(db, pub)

	got, err := svc.MonitorFP(context.Background(), 24*time.Hour, 50)
	if err != nil {
		t.Fatal(err)
	}
	_ = got
	var quarantined bool
	for _, e := range db.execs {
		if strings.Contains(e.sql, "curate_state='quarantined'") {
			quarantined = true
		}
	}
	if !quarantined {
		t.Fatal("expected a quarantine UPDATE")
	}
	if len(pub.subjects) != 1 || pub.subjects[0] != "rules.invalidate" {
		t.Fatalf("published = %v, want [rules.invalidate]", pub.subjects)
	}
}
