// Package rollback — execute.go dispatches a RollbackPlan's inverse operations to
// an endpoint (Ph3 of docs/design/ロールバック(Storyline相当)設計.md). The dispatch
// itself is a thin, deterministic orchestration over a Commander, so it is unit
// testable with a fake; the API handler wraps it (Plan → Execute → MarkReverted).
package rollback

import "context"

// Commander dispatches file operations to an endpoint. *store.CommandStore satisfies
// it (RestoreFile is the existing quarantine-restore verb; DeleteFile is added for
// rollback). Kept minimal so rollback need not import the store package.
type Commander interface {
	// RestoreFile writes the pre-image backup (backupRef) back to restorePath.
	RestoreFile(ctx context.Context, agentID, backupRef, restorePath string) error
	// DeleteFile removes an incident-created artefact at path.
	DeleteFile(ctx context.Context, agentID, path, reason string) error
}

// ExecOutcome is the per-operation result of executing a rollback plan.
type ExecOutcome struct {
	Path    string `json:"path"`
	Action  string `json:"action"`
	Success bool   `json:"success"`
	Skipped bool   `json:"skipped"` // NeedsManual op — not dispatched
	Reason  string `json:"reason,omitempty"`
	Error   string `json:"error,omitempty"`
}

// Execute dispatches each op in the plan to agentID and returns the per-op outcome.
// NeedsManual ops (no pre-image backup) are skipped — never dispatched — so the
// caller can report them for manual handling rather than silently succeeding.
func Execute(ctx context.Context, agentID string, plan RollbackPlan, cmd Commander) []ExecOutcome {
	outcomes := make([]ExecOutcome, 0, len(plan.Ops))
	for _, op := range plan.Ops {
		o := ExecOutcome{Path: op.Path, Action: op.Action}
		if op.NeedsManual {
			o.Skipped = true
			o.Reason = op.Reason
			outcomes = append(outcomes, o)
			continue
		}
		var err error
		switch op.Action {
		case ActionRestore:
			err = cmd.RestoreFile(ctx, agentID, op.BackupRef, op.Path)
		case ActionDelete:
			err = cmd.DeleteFile(ctx, agentID, op.Path, "rollback: remove incident-created file")
		default:
			o.Skipped = true
			o.Reason = "unknown action '" + op.Action + "'"
			outcomes = append(outcomes, o)
			continue
		}
		if err != nil {
			o.Error = err.Error()
		} else {
			o.Success = true
		}
		outcomes = append(outcomes, o)
	}
	return outcomes
}

// SucceededPaths returns the paths whose ops executed successfully — the set the
// caller marks reverted in the journal.
func SucceededPaths(outcomes []ExecOutcome) []string {
	var paths []string
	for _, o := range outcomes {
		if o.Success {
			paths = append(paths, o.Path)
		}
	}
	return paths
}
