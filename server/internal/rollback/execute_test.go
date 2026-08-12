package rollback

import (
	"context"
	"errors"
	"testing"
)

type fakeCommander struct {
	restored [][2]string // {backupRef, path}
	deleted  []string
	failPath string // path whose dispatch returns an error
}

func (f *fakeCommander) RestoreFile(_ context.Context, _, backupRef, restorePath string) error {
	if restorePath == f.failPath {
		return errors.New("dispatch failed")
	}
	f.restored = append(f.restored, [2]string{backupRef, restorePath})
	return nil
}
func (f *fakeCommander) DeleteFile(_ context.Context, _, path, _ string) error {
	if path == f.failPath {
		return errors.New("dispatch failed")
	}
	f.deleted = append(f.deleted, path)
	return nil
}

// TestExecute_DispatchesRestoreAndDelete verifies restore ops call RestoreFile with the
// backup ref and delete ops call DeleteFile.
func TestExecute_DispatchesRestoreAndDelete(t *testing.T) {
	plan := RollbackPlan{Ops: []RollbackOp{
		{Path: "/home/u/a.docx", Action: ActionRestore, BackupRef: "bk-1"},
		{Path: "/tmp/dropper", Action: ActionDelete},
	}}
	cmd := &fakeCommander{}
	out := Execute(context.Background(), "agent-1", plan, cmd)

	if len(cmd.restored) != 1 || cmd.restored[0] != [2]string{"bk-1", "/home/u/a.docx"} {
		t.Fatalf("restore not dispatched correctly: %+v", cmd.restored)
	}
	if len(cmd.deleted) != 1 || cmd.deleted[0] != "/tmp/dropper" {
		t.Fatalf("delete not dispatched correctly: %+v", cmd.deleted)
	}
	if len(SucceededPaths(out)) != 2 {
		t.Fatalf("both ops should succeed, got %+v", out)
	}
}

// TestExecute_NeedsManual_Skipped verifies a NeedsManual op is never dispatched and is
// reported as skipped.
func TestExecute_NeedsManual_Skipped(t *testing.T) {
	plan := RollbackPlan{Ops: []RollbackOp{
		{Path: "/home/u/secret.key", Action: ActionRestore, BackupRef: "", NeedsManual: true, Reason: "no backup"},
	}}
	cmd := &fakeCommander{}
	out := Execute(context.Background(), "agent-1", plan, cmd)

	if len(cmd.restored) != 0 {
		t.Fatalf("NeedsManual op must NOT be dispatched, got %+v", cmd.restored)
	}
	if len(out) != 1 || !out[0].Skipped || out[0].Success {
		t.Fatalf("NeedsManual op should be skipped, got %+v", out[0])
	}
	if len(SucceededPaths(out)) != 0 {
		t.Fatal("skipped op must not count as succeeded")
	}
}

// TestExecute_DispatchError_Surfaced verifies a commander error is surfaced per-op and
// that op is not counted as succeeded (so it is not marked reverted).
func TestExecute_DispatchError_Surfaced(t *testing.T) {
	plan := RollbackPlan{Ops: []RollbackOp{
		{Path: "/a", Action: ActionRestore, BackupRef: "bk"},
		{Path: "/b", Action: ActionDelete},
	}}
	cmd := &fakeCommander{failPath: "/a"}
	out := Execute(context.Background(), "agent-1", plan, cmd)

	var aOut ExecOutcome
	for _, o := range out {
		if o.Path == "/a" {
			aOut = o
		}
	}
	if aOut.Success || aOut.Error == "" {
		t.Fatalf("/a dispatch error should be surfaced, got %+v", aOut)
	}
	// /b still succeeds and is the only reverted path.
	if paths := SucceededPaths(out); len(paths) != 1 || paths[0] != "/b" {
		t.Fatalf("only /b should succeed, got %+v", paths)
	}
}
