package rollback

import (
	"testing"
	"time"
)

func at(sec int) time.Time { return time.Unix(int64(sec), 0).UTC() }

// find returns the op for a path, or a zero op with found=false.
func find(p RollbackPlan, path string) (RollbackOp, bool) {
	for _, op := range p.Ops {
		if op.Path == path {
			return op, true
		}
	}
	return RollbackOp{}, false
}

// TestPlan_CreatedFile_InverseIsDelete: a file the incident created is removed.
func TestPlan_CreatedFile_InverseIsDelete(t *testing.T) {
	p := Plan("inc-1", []JournalEntry{
		{Path: "/tmp/dropper.sh", Operation: OpCreate, OccurredAt: at(1)},
	})
	op, ok := find(p, "/tmp/dropper.sh")
	if !ok || op.Action != ActionDelete || op.NeedsManual {
		t.Fatalf("created file should invert to auto delete, got %+v", op)
	}
}

// TestPlan_ModifiedFile_RestoresPreImage: an encrypted/overwritten file restores the
// pre-image captured before the FIRST modification.
func TestPlan_ModifiedFile_RestoresPreImage(t *testing.T) {
	p := Plan("inc-1", []JournalEntry{
		{Path: "/home/u/report.docx", Operation: OpModify, BackupRef: "bk-1", OccurredAt: at(5)},
		{Path: "/home/u/report.docx", Operation: OpModify, BackupRef: "bk-2", OccurredAt: at(9)},
	})
	op, ok := find(p, "/home/u/report.docx")
	if !ok || op.Action != ActionRestore || op.BackupRef != "bk-1" || op.NeedsManual {
		t.Fatalf("multi-modify should restore the FIRST pre-image bk-1, got %+v", op)
	}
}

// TestPlan_DeletedFile_RestoresPreImage: a deleted file is restored from its pre-image.
func TestPlan_DeletedFile_RestoresPreImage(t *testing.T) {
	p := Plan("inc-1", []JournalEntry{
		{Path: "/etc/passwd.bak", Operation: OpDelete, BackupRef: "bk-9", OccurredAt: at(3)},
	})
	op, _ := find(p, "/etc/passwd.bak")
	if op.Action != ActionRestore || op.BackupRef != "bk-9" {
		t.Fatalf("deleted file should restore pre-image, got %+v", op)
	}
}

// TestPlan_CreatedThenDeleted_NetDelete: create then delete by the incident → inverse is
// delete (safe no-op if already gone), not a restore.
func TestPlan_CreatedThenDeleted_NetDelete(t *testing.T) {
	p := Plan("inc-1", []JournalEntry{
		{Path: "/tmp/x", Operation: OpCreate, OccurredAt: at(1)},
		{Path: "/tmp/x", Operation: OpDelete, BackupRef: "bk-x", OccurredAt: at(2)},
	})
	op, _ := find(p, "/tmp/x")
	if op.Action != ActionDelete || op.NeedsManual {
		t.Fatalf("created-then-deleted should invert to delete, got %+v", op)
	}
}

// TestPlan_MissingBackup_NeedsManual: a modify with no pre-image is flagged, not dropped.
func TestPlan_MissingBackup_NeedsManual(t *testing.T) {
	p := Plan("inc-1", []JournalEntry{
		{Path: "/home/u/secret.key", Operation: OpModify, BackupRef: "", OccurredAt: at(4)},
	})
	op, ok := find(p, "/home/u/secret.key")
	if !ok || !op.NeedsManual {
		t.Fatalf("missing backup must be flagged NeedsManual, got %+v", op)
	}
	if p.NeedsManualCount() != 1 {
		t.Fatalf("NeedsManualCount = %d, want 1", p.NeedsManualCount())
	}
}

// TestPlan_FirstOpDecisive_DeleteThenModifyIrrelevant: earliest op determines the inverse
// even when timestamps are supplied out of order.
func TestPlan_FirstOpDecisive_OutOfOrder(t *testing.T) {
	p := Plan("inc-1", []JournalEntry{
		{Path: "/data/db", Operation: OpModify, BackupRef: "bk-late", OccurredAt: at(20)},
		{Path: "/data/db", Operation: OpDelete, BackupRef: "bk-first", OccurredAt: at(10)}, // earlier
	})
	op, _ := find(p, "/data/db")
	if op.Action != ActionRestore || op.BackupRef != "bk-first" {
		t.Fatalf("earliest op (bk-first) must decide the inverse, got %+v", op)
	}
}

// TestPlan_DeterministicOrder: ops are sorted by path regardless of input order.
func TestPlan_DeterministicOrder(t *testing.T) {
	p := Plan("inc-1", []JournalEntry{
		{Path: "/z", Operation: OpCreate, OccurredAt: at(1)},
		{Path: "/a", Operation: OpCreate, OccurredAt: at(2)},
		{Path: "/m", Operation: OpModify, BackupRef: "b", OccurredAt: at(3)},
	})
	if len(p.Ops) != 3 || p.Ops[0].Path != "/a" || p.Ops[1].Path != "/m" || p.Ops[2].Path != "/z" {
		t.Fatalf("ops must be path-sorted, got %+v", p.Ops)
	}
}

// TestPlan_EmptyAndBlankPaths: no entries → empty plan; blank paths are ignored.
func TestPlan_EmptyAndBlankPaths(t *testing.T) {
	if len(Plan("inc-1", nil).Ops) != 0 {
		t.Fatal("empty journal should yield empty plan")
	}
	p := Plan("inc-1", []JournalEntry{{Path: "", Operation: OpCreate, OccurredAt: at(1)}})
	if len(p.Ops) != 0 {
		t.Fatalf("blank path should be ignored, got %+v", p.Ops)
	}
}
