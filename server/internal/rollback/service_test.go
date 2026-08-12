package rollback

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ── minimal fake RollbackDB (pgx.Rows / Exec) ──────────────────────────────

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
		case *time.Time:
			*d = row[k].(time.Time)
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

type fakeDB struct {
	queryRows [][]any
	execs     []fakeExec
	updated   int64
}

func (f *fakeDB) Query(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
	return &fakeRows{data: f.queryRows}, nil
}
func (f *fakeDB) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	f.execs = append(f.execs, fakeExec{sql: sql, args: args})
	if strings.HasPrefix(strings.TrimSpace(sql), "UPDATE") {
		return pgconn.NewCommandTag("UPDATE " + itoa(f.updated)), nil
	}
	return pgconn.NewCommandTag("INSERT 0 1"), nil
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func t(sec int) time.Time { return time.Unix(int64(sec), 0).UTC() }

// TestService_RecordChange_Insert verifies an INSERT with NULL for empty optionals.
func TestService_RecordChange_Insert(t0 *testing.T) {
	db := &fakeDB{}
	svc := NewRollbackService(db)
	err := svc.RecordChange(context.Background(), ChangeRecord{
		IncidentID: "inc-1", AgentID: "a1", Path: "/tmp/x", Operation: OpCreate, OccurredAt: t(1),
	})
	if err != nil {
		t0.Fatalf("RecordChange: %v", err)
	}
	if len(db.execs) != 1 || !strings.Contains(db.execs[0].sql, "INSERT INTO remediation_journal") {
		t0.Fatalf("expected one INSERT, got %+v", db.execs)
	}
	// alert_id (arg 2) and backup_ref (arg 6) were empty → stored as NULL (nil).
	args := db.execs[0].args
	if args[1] != nil {
		t0.Errorf("empty alert_id should be nil, got %v", args[1])
	}
	if args[5] != nil {
		t0.Errorf("empty backup_ref should be nil, got %v", args[5])
	}
}

// TestService_Plan_LoadsAndInverts verifies Plan loads journal rows and delegates to
// the pure planner (a modify with a pre-image → restore).
func TestService_Plan_LoadsAndInverts(t0 *testing.T) {
	db := &fakeDB{queryRows: [][]any{
		{"/home/u/report.docx", OpModify, "bk-1", t(5)},
		{"/tmp/dropper", OpCreate, "", t(6)},
	}}
	svc := NewRollbackService(db)
	plan, err := svc.Plan(context.Background(), "inc-1")
	if err != nil {
		t0.Fatalf("Plan: %v", err)
	}
	if len(plan.Ops) != 2 {
		t0.Fatalf("expected 2 ops, got %+v", plan.Ops)
	}
	// path-sorted: /home/u/report.docx (restore) then /tmp/dropper (delete)
	if plan.Ops[0].Action != ActionRestore || plan.Ops[0].BackupRef != "bk-1" {
		t0.Errorf("first op should restore bk-1, got %+v", plan.Ops[0])
	}
	if plan.Ops[1].Action != ActionDelete {
		t0.Errorf("second op should delete created file, got %+v", plan.Ops[1])
	}
}

// TestService_Preview_EqualsPlan sanity: Preview delegates to Plan.
func TestService_Preview_EqualsPlan(t0 *testing.T) {
	db := &fakeDB{queryRows: [][]any{{"/a", OpDelete, "bk", t(1)}}}
	svc := NewRollbackService(db)
	plan, err := svc.Preview(context.Background(), "inc-1")
	if err != nil || len(plan.Ops) != 1 || plan.Ops[0].Action != ActionRestore {
		t0.Fatalf("Preview should return the restore plan, got %+v err=%v", plan.Ops, err)
	}
}

// TestService_MarkReverted verifies an UPDATE is issued and rows-affected returned.
func TestService_MarkReverted(t0 *testing.T) {
	db := &fakeDB{updated: 3}
	svc := NewRollbackService(db)
	n, err := svc.MarkReverted(context.Background(), "inc-1", []string{"/a", "/b", "/c"})
	if err != nil {
		t0.Fatalf("MarkReverted: %v", err)
	}
	if n != 3 {
		t0.Errorf("rows affected = %d, want 3", n)
	}
	if len(db.execs) != 1 || !strings.HasPrefix(strings.TrimSpace(db.execs[0].sql), "UPDATE") {
		t0.Fatalf("expected one UPDATE, got %+v", db.execs)
	}
}

// TestService_MarkReverted_NoPaths is a no-op that issues no SQL.
func TestService_MarkReverted_NoPaths(t0 *testing.T) {
	db := &fakeDB{}
	svc := NewRollbackService(db)
	if n, err := svc.MarkReverted(context.Background(), "inc-1", nil); n != 0 || err != nil {
		t0.Fatalf("no paths should be a no-op, got n=%d err=%v", n, err)
	}
	if len(db.execs) != 0 {
		t0.Fatalf("no paths should issue no SQL, got %+v", db.execs)
	}
}
