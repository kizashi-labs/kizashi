package detection

import "sort"

// Curate decides which SigmaHQ-synced rules to enable. The syncer imports rules
// disabled (enabled=false) to avoid a flood: enabling thousands at once both
// reloads the whole rule set (a DB connection spike — "too many clients") and
// turns on noisy rules wholesale. Curate turns them on safely and incrementally:
//
//  1. field gate — a rule whose selected fields the telemetry cannot populate is
//     inert ("false green"); it stays Pending, never enabled.
//  2. per-category cap — at most perCategoryLimit rules are enabled per round per
//     logsource category, so each curate round reloads a bounded batch. Remaining
//     supported rules are Deferred to the next round.
//
// This is the pure decision used by the (DB-side) curate step; keeping it pure
// makes the flood-control and the gate independently testable.

// SyncedRule is a curate candidate: a synced rule that is currently disabled.
type SyncedRule struct {
	ID       string // rules.id
	Category string // logsource category (process_creation/registry/image_load/…)
	Content  string // raw Sigma YAML
}

// CuratePlan is the outcome of a curate round.
type CuratePlan struct {
	Enable    []string // field-supported, within this round's per-category cap → turn on
	Deferred  []string // field-supported but over the cap this round → next round
	Pending   []string // field-unsupported → keep disabled (would be a false green)
	Duplicate []string // technique×logsource already covered by a builtin → keep disabled
}

// CurateBatch plans one curate round over the given disabled synced rules.
// perCategoryLimit <= 0 means "no cap" (enable every supported rule). The supported
// set should be SupportedSigmaFields(), computed once by the caller. Results are
// deterministic (rules considered in ID order) so successive rounds advance
// predictably and a re-run with the same input is stable.
//
// Equivalent to CurateBatchWith without the builtin-overlap gate.
func CurateBatch(rules []SyncedRule, perCategoryLimit int, supported map[string]bool) CuratePlan {
	return CurateBatchWith(rules, perCategoryLimit, supported, nil)
}

// CurateBatchWith is CurateBatch plus gate 3: a rule whose technique×logsource the
// builtin ruleset already covers is not enabled, because both engines consume the
// same event stream and would each raise an alert for it (see
// curate_builtin_coverage.go). Pass nil for coverage to skip the gate.
//
// Ordering matters. The field gate runs first because an inert rule is inert
// whether or not it overlaps. The overlap gate runs before the per-category cap so
// a duplicate never consumes a slot that a rule covering something new could use.
func CurateBatchWith(rules []SyncedRule, perCategoryLimit int, supported map[string]bool, builtinCov map[string]bool) CuratePlan {
	sorted := append([]SyncedRule(nil), rules...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })

	plan := CuratePlan{}
	enabledPerCat := map[string]int{}
	for _, r := range sorted {
		ok, _ := RuleFieldSupportWith(r.Content, supported)
		if !ok {
			plan.Pending = append(plan.Pending, r.ID)
			continue
		}
		if duplicatesBuiltin(r, builtinCov) {
			plan.Duplicate = append(plan.Duplicate, r.ID)
			continue
		}
		if perCategoryLimit > 0 && enabledPerCat[r.Category] >= perCategoryLimit {
			plan.Deferred = append(plan.Deferred, r.ID)
			continue
		}
		enabledPerCat[r.Category]++
		plan.Enable = append(plan.Enable, r.ID)
	}
	return plan
}
