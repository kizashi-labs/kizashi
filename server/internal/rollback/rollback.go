// Package rollback reconstructs the file-system impact of an incident into the
// minimal set of operations that restore the pre-incident state — the "Storyline"
// brain of the rollback feature (docs/design/ロールバック(Storyline相当)設計.md, Ph1).
//
// It is pure logic over a journal of file changes (no DB, no filesystem), so the
// inversion rules are deterministic and unit-testable. The surrounding phases —
// the remediation_journal table, the RollbackService DB wiring, the API, and the
// agent-side copy-on-write pre-image backup — build on this core.
package rollback

import (
	"sort"
	"time"
)

// Operation values a journal entry can carry.
const (
	OpCreate = "create"
	OpModify = "modify"
	OpDelete = "delete"
)

// Rollback action values.
const (
	ActionRestore = "restore" // write the pre-image back to Path
	ActionDelete  = "delete"  // remove an attacker-created artifact at Path
)

// JournalEntry is one reversible file-system change attributed to an incident.
type JournalEntry struct {
	Path       string    // file the operation targeted
	Operation  string    // OpCreate | OpModify | OpDelete
	BackupRef  string    // agent-side pre-image backup id (set for modify/delete of a pre-existing file)
	OccurredAt time.Time // used to determine the FIRST operation on each path
}

// RollbackOp is one inverse operation to undo an incident's effect on a path.
type RollbackOp struct {
	Path        string
	Action      string // ActionRestore | ActionDelete
	BackupRef   string // pre-image to restore (empty for delete)
	NeedsManual bool   // restore required but no pre-image backup is available
	Reason      string
}

// RollbackPlan is the ordered set of inverse operations for an incident.
type RollbackPlan struct {
	IncidentID string
	Ops        []RollbackOp
}

// NeedsManualCount returns how many ops cannot be executed automatically because
// their pre-image backup is missing (surfaced so "restored" never silently lies).
func (p RollbackPlan) NeedsManualCount() int {
	n := 0
	for _, op := range p.Ops {
		if op.NeedsManual {
			n++
		}
	}
	return n
}

// Plan reconstructs, from an incident's journal entries, the minimal set of
// operations that restore the pre-incident state.
//
// The FIRST operation on each path is decisive:
//   - first op create → the file did not exist before → inverse is delete;
//   - first op modify/delete → the file existed before → inverse is restore of the
//     pre-image captured before that first change (later modifications are irrelevant;
//     we always restore the pre-incident content).
//
// A path whose first op is modify/delete but whose pre-image backup_ref is empty
// yields a NeedsManual restore op, so an unrecoverable change is reported rather
// than dropped. Output is sorted by path for deterministic previews.
func Plan(incidentID string, entries []JournalEntry) RollbackPlan {
	// Find the earliest entry per path (stable: OccurredAt, then original order).
	type firstRec struct {
		entry JournalEntry
		idx   int
	}
	firsts := make(map[string]firstRec)
	for i, e := range entries {
		if e.Path == "" {
			continue
		}
		cur, ok := firsts[e.Path]
		if !ok || e.OccurredAt.Before(cur.entry.OccurredAt) ||
			(e.OccurredAt.Equal(cur.entry.OccurredAt) && i < cur.idx) {
			firsts[e.Path] = firstRec{entry: e, idx: i}
		}
	}

	ops := make([]RollbackOp, 0, len(firsts))
	for path, fr := range firsts {
		first := fr.entry
		switch first.Operation {
		case OpCreate:
			// Created by the incident → remove it. If it was later deleted by the
			// incident too, deleting a non-existent file is a safe no-op downstream.
			ops = append(ops, RollbackOp{
				Path:   path,
				Action: ActionDelete,
				Reason: "incident-created file — remove artifact",
			})
		case OpModify, OpDelete:
			op := RollbackOp{
				Path:      path,
				Action:    ActionRestore,
				BackupRef: first.BackupRef,
				Reason:    "restore pre-incident content (" + first.Operation + ")",
			}
			if first.BackupRef == "" {
				op.NeedsManual = true
				op.Reason = "pre-image backup missing — manual restore required (" + first.Operation + ")"
			}
			ops = append(ops, op)
		default:
			// Unknown operation: surface as manual so it is not silently ignored.
			ops = append(ops, RollbackOp{
				Path:        path,
				Action:      ActionRestore,
				NeedsManual: true,
				Reason:      "unknown operation '" + first.Operation + "' — manual review",
			})
		}
	}

	sort.Slice(ops, func(i, j int) bool { return ops[i].Path < ops[j].Path })
	return RollbackPlan{IncidentID: incidentID, Ops: ops}
}
