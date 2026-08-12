package detection

import (
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// Detection runs in two processes that subscribe to the SAME event stream:
// server-api's AlertPipeline evaluates the builtin Sigma rules in
// sigma_builtins.go ("[Sigma] …"), and server-detect's Engine evaluates the DB
// rules table ("[SIGMA] …"). When a synced SigmaHQ rule covers a technique the
// builtins already cover in the same logsource, ONE event produces TWO alerts.
//
// This is not hypothetical: in the benign-only FP soak (20 hosts, 1.67 host-days,
// 445 alerts) eleven such pairs accounted for ~60 alerts — about 13% of the total.
// Three of them were migration-seeded and could be disabled directly (migration
// 373); the remaining eight were source='sigmahq' rows that curate had enabled,
// so they will simply come back — and more with them — as the SigmaHQ feed grows.
// The duplication is structural, so the gate belongs in curate's enable decision.

// builtinCoverageKey is the unit of overlap: one MITRE technique observed in one
// logsource category. Both halves matter — the same technique seen through
// process_creation and through file_event are genuinely different detections and
// must not suppress each other.
func builtinCoverageKey(technique, category string) string {
	return strings.ToUpper(technique) + "|" + category
}

var (
	builtinCoverageOnce sync.Once
	builtinCoverageSet  map[string]bool
)

// BuiltinCoverage returns the set of technique×category pairs already covered by
// the builtin Sigma rules. Computed once: builtinSigmaRules is a compile-time
// constant, and curate rounds run on a schedule.
func BuiltinCoverage() map[string]bool {
	builtinCoverageOnce.Do(func() {
		builtinCoverageSet = make(map[string]bool)
		for _, ruleYAML := range builtinSigmaRules {
			cat := RuleCategory(ruleYAML)
			for _, tech := range sigmaTechniques(ruleYAML) {
				builtinCoverageSet[builtinCoverageKey(tech, cat)] = true
			}
		}
	})
	return builtinCoverageSet
}

// sigmaTechniques extracts EVERY MITRE technique tagged on a Sigma rule
// ("attack.t1087.001" → "T1087.001"). Unlike parseMITRETechFromTags — which
// deliberately returns only the first tag because an alert carries one primary
// technique — overlap detection needs all of them: a rule tagged with two
// techniques duplicates a builtin that covers either one.
func sigmaTechniques(ruleYAML string) []string {
	var doc struct {
		Tags []string `yaml:"tags"`
	}
	if err := yaml.Unmarshal([]byte(ruleYAML), &doc); err != nil {
		return nil
	}
	var out []string
	for _, tag := range doc.Tags {
		lower := strings.ToLower(strings.TrimSpace(tag))
		if !strings.HasPrefix(lower, "attack.t") {
			continue // attack.execution, attack.persistence, … are tactics, not techniques
		}
		out = append(out, strings.ToUpper(strings.TrimPrefix(lower, "attack.")))
	}
	return out
}

// duplicatesBuiltin reports whether a synced rule's technique×category is already
// covered by a builtin. An untagged rule is never treated as a duplicate: without
// a technique there is nothing to compare, and silently deferring it would hide a
// detection for a reason no one could see in the status view.
func duplicatesBuiltin(r SyncedRule, coverage map[string]bool) bool {
	if len(coverage) == 0 {
		return false
	}
	for _, tech := range sigmaTechniques(r.Content) {
		if coverage[builtinCoverageKey(tech, r.Category)] {
			return true
		}
	}
	return false
}
