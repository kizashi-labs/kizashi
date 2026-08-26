package rules

// Migration-rule extraction harness.
//
// The detection-server RuleEngine is populated at runtime from the `rules`
// table in Postgres (cmd/detection/main.go → ruleStore.ListEnabled). The
// shipped rules live as INSERT statements in server/migrations/*.sql. Until now
// the only container-testable coverage came from tests that COPIED a rule's
// YAML inline (e.g. linux_collection_rule_test.go's const linuxArchiveRuleYAML),
// carrying a "if you edit the SQL, update these copies too" drift hazard: the
// copy can silently diverge from the shipped rule so the test passes while the
// production rule is broken.
//
// This harness instead loads the ACTUAL migration SQL — the exact bytes the DB
// engine runs — so regression tests assert against the shipped rules with zero
// drift. It is the DB-engine equivalent of attack_coverage_test.go /
// EvaluateEnvelope, which only exercises the api-server builtin SigmaEvaluator.
//
// The extractor is deliberately narrow (only `INSERT INTO rules (...)`) and
// self-validating (see TestMigrationExtractor_SelfCheck): if a future migration
// uses a shape the tokenizer cannot parse, the self-check fails loudly rather
// than silently dropping rules and under-reporting coverage.

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// migrationsDir is the path to the SQL migrations relative to this package
// (server/internal/detection/rules → up 3 → server → migrations).
const migrationsDir = "../../../migrations"

// insertHeaderRe matches the start of an `INSERT INTO rules (col, col, ...)`
// statement, capturing the column list and the mode keyword. Migrations use two
// insertion shapes: the `VALUES (…),(…)` form and the idempotent `SELECT …
// WHERE NOT EXISTS (…)` form (a whole class of correlation/kill-chain rules,
// migrations 266/267/274/283-312, ships via the SELECT form). Both must be
// extracted or those rules are silently uncovered. \brules\b avoids rules_*.
var insertHeaderRe = regexp.MustCompile(`(?is)INSERT\s+INTO\s+rules\s*\(([^)]*)\)\s*(VALUES|SELECT)`)

// updateContentRe matches `UPDATE rules SET content = $$…$$ … WHERE name = '…'`,
// the form migrations use to FIX an already-shipped rule (288 auth_bruteforce_fix,
// 291 network_behavioral_field_fix, 366 certutil parity split).
//
// Without this the extractor returned each rule's ORIGINAL insert text, so the
// suite that exists to "lock the shipped rules against drift" was locking the
// pre-fix content — the corrected rule that actually reaches production was never
// under test. Migration 288 exists precisely because those rules were inert; the
// harness could not have told the difference.
//
// The assignment list is parsed generically rather than assuming `content` comes
// first. The earlier pattern required `SET content = $$…$$` literally, so
// migration 373's `SET severity = 4, content = $$…$$` matched NOTHING — not just
// the severity, the content rewrite too. An extractor that silently ignores a
// statement shape is the same drift hazard this harness exists to remove, which
// is why TestEveryUpdateRulesStatementIsUnderstood below refuses to let an
// unparsed `UPDATE rules SET` pass quietly.
//
// Group 1 = assignments before content, 2 = content, 3 = assignments after it,
// 4 = name. Group 1 excludes `$` (so it cannot swallow the dollar-quote) AND `;`
// (so it cannot reach forward into a LATER statement's `content =`). Without the
// `;` the IN-form pattern started at migration 241's replace() statement, ran
// group 1 across that statement's terminator, and bound to the NEXT statement's
// content — the same start-too-early failure dollarBody describes, one clause up.
var updateContentRe = regexp.MustCompile(`(?is)UPDATE\s+rules\s+SET\s+([^$;]*?)content\s*=\s*\$\$` + dollarBody + `\$\$([^;]*?)WHERE\s+name\s*=\s*'([^']*)'`)

// updateContentNamedRe matches the OPENING of a named-dollar-quote content
// rewrite: `UPDATE rules SET … content = $SIGMA$`.
//
// Migrations do not only use `$$`. The Sigma bodies are written with a NAMED tag
// (`$SIGMA$…$SIGMA$`, and `$SEQ$` for the sequence rules) because the YAML itself
// contains `$$`-hostile text. updateContentRe above is `$$`-only, so every one of
// those statements was invisible to the extractor — 14 of them across migrations
// 315/324/325/326/329/340/371/372. The harness then locked each rule's ORIGINAL
// insert text while production ran the corrected one, which is precisely the drift
// this file exists to eliminate. TestEveryUpdateRulesStatementIsUnderstood is what
// surfaced it.
//
// Only the opening tag is matched here. RE2 has no backreferences, so the closing
// `$TAG$` cannot be expressed in the same pattern; applyNamedContentUpdates scans
// forward for it. The tag must be non-empty ([A-Za-z_]+) so this never overlaps
// updateContentRe's `$$` form and double-claims a statement in the gate.
var updateContentNamedRe = regexp.MustCompile(`(?is)UPDATE\s+rules\s+SET\s+[^$;]*?content\s*=\s*\$([A-Za-z_]+)\$`)

// updateNamedTargetRe pulls the rule name out of the tail of such a statement.
var updateNamedTargetRe = regexp.MustCompile(`(?is)WHERE\s+name\s*=\s*'([^']*)'`)

// applyNamedContentUpdates is the named-tag counterpart of the `$$` handling in
// applyContentUpdates. Written as a forward scan rather than a regex for the
// backreference reason above.
func applyNamedContentUpdates(rules []*DetectionRule, sql string) {
	if !touchesRulesTable(sql) {
		return
	}
	for _, loc := range updateContentNamedRe.FindAllStringSubmatchIndex(sql, -1) {
		closeTag := "$" + sql[loc[2]:loc[3]] + "$"
		body := sql[loc[1]:]
		end := strings.Index(body, closeTag)
		if end < 0 {
			continue // unterminated dollar quote; leave the rule as inserted
		}
		content := body[:end]
		// The name lives in this statement's tail. Stop at the terminator so a
		// WHERE from the NEXT statement cannot be picked up — the same
		// start-too-early hazard dollarBody describes for the `$$` form.
		tail := body[end+len(closeTag):]
		if semi := strings.Index(tail, ";"); semi >= 0 {
			tail = tail[:semi]
		}
		nm := updateNamedTargetRe.FindStringSubmatch(tail)
		if nm == nil {
			continue
		}
		for _, r := range rules {
			if r.Name == nm[1] {
				r.Content = content
			}
		}
	}
}

// dollarBody is the interior of a `$$…$$` literal, written so it can never cross
// its own closing delimiter.
//
// The obvious spelling — `\$\$(.*?)\$\$` — cannot do that, and the failure is not
// theoretical. In migration 241 the IN-form pattern matched from the FIRST
// `UPDATE rules SET` in the file, then let the lazy body run past that
// statement's closing `$$`, past a whole second statement, and stop at the
// THIRD statement's `$$ WHERE name IN (…)`. One match, spanning three
// statements: the two /etc/passwd rules named in that IN list would have been
// assigned the first statement's YAML, and the statement that actually rewrites
// them would have gone unclaimed. Laziness only guarantees the SHORTEST match
// from a given start — it does not stop the match from starting too early.
//
// `(?:[^$]|\$[^$])*` is the tempered form: a `$` may appear in the body only
// when the next byte is not another `$`, so the first `$$` encountered
// necessarily terminates it. RE2 has no lookahead, which rules out the usual
// `(?:(?!\$\$).)*`.
const dollarBody = `((?:[^$]|\$[^$])*)`

// NOTE: every "assignments between the content and the WHERE" group is [^;]*?,
// not (.*?) — a `;` can never appear between an assignment list and its WHERE,
// so it is the correct fence for that span, just as dollarBody is for the body.

// updateFieldsRe matches an UPDATE that changes flags but NOT content, e.g.
// migration 313's `SET enabled = FALSE, updated_at = NOW()`. Excluding `$` and
// `;` from the assignment list keeps it from ever matching a content-bearing
// statement, so the two patterns partition the input instead of overlapping.
//
// This shape was invisible before: the harness reported "Test Custom Rule" as
// enabled while migration 313 had disabled it, precisely because no pattern
// covered a content-less UPDATE.
// The name predicate is accepted after AND as well as directly after WHERE.
// Migration 326 disables a superseded rule with
// `WHERE type = 'sigma' AND name = '…' AND enabled = TRUE`, and a WHERE-only
// pattern skipped it — the harness kept the rule enabled while production
// disabled it. Group 1 still excludes `;` and `$`, so widening the keyword
// cannot reach across a statement terminator or into a dollar-quoted body.
var updateFieldsRe = regexp.MustCompile(`(?is)UPDATE\s+rules\s+SET\s+([^$;]*?)(?:WHERE|AND)\s+name\s*=\s*'([^']*)'`)

// The same two shapes keyed by id instead of name. Migrations use both.
var (
	updateContentByIDRe = regexp.MustCompile(`(?is)UPDATE\s+rules\s+SET\s+([^$;]*?)content\s*=\s*\$\$` + dollarBody + `\$\$([^;]*?)WHERE\s+id\s*=\s*'([^']*)'`)
	updateFieldsByIDRe  = regexp.MustCompile(`(?is)UPDATE\s+rules\s+SET\s+([^$;]*?)WHERE\s+id\s*=\s*'([^']*)'`)
)

// replace(content, 'from', 'to') — a surgical edit to an already-shipped rule
// rather than a full rewrite (241, 292, 317, 357 use it). Modelling it matters:
// these are the migrations that FIX a broken rule, so treating them as no-ops
// means the harness validates the broken version.
var updateReplaceRe = regexp.MustCompile(`(?is)UPDATE\s+rules\s+SET\s+content\s*=\s*replace\(\s*content\s*,\s*'((?:[^']|'')*)'\s*,\s*'((?:[^']|'')*)'\s*\)([^;]*?)WHERE\s+(name|id)\s*=\s*'([^']*)'`)

// Rules selected by their CONTENT rather than by name or id. Migration 374
// disables DB rules a builtin already covers, and it can key on neither the name
// (which differs between the two sources) nor the id (which varies per
// environment), so it matches the YAML text itself:
//
//	UPDATE rules SET enabled = false, updated_at = now()
//	WHERE content LIKE '%title: Lateral Movement via RDP%'
//	  AND content NOT LIKE '%xfreerdp%';
//
// This one IS evaluable — DetectionRule carries Content — which separates it
// from the source/curate_state predicates in unevaluablePredicates. Leaving it
// unmodelled would make the harness report a DISABLED rule as enabled, the same
// silent drift this file exists to prevent: migration 374 exists precisely
// because those rules double-count against builtins.
var (
	updateFieldsByContentRe = regexp.MustCompile(
		`(?is)UPDATE\s+rules\s+SET\s+([^$;]*?)WHERE\s+content\s+LIKE\s+'%([^%']*)%'((?:\s+AND\s+content\s+NOT\s+LIKE\s+'%[^%']*%')*)`)
	contentNotLikeRe = regexp.MustCompile(`(?is)AND\s+content\s+NOT\s+LIKE\s+'%([^%']*)%'`)
)

// updateStmtStartRe finds where each `UPDATE rules SET` begins, so the harness
// can prove one of the patterns above claimed every one that matters.
var updateStmtStartRe = regexp.MustCompile(`(?is)UPDATE\s+rules\s+SET`)

// updateGateRe is the cheap pre-filter: a tiny automaton that answers "could any
// of the eight UPDATE patterns match this file at all?".
//
// It must stay a strict SUPERSET of what those patterns can match, or the fast
// path silently disagrees with the slow one — the exact failure this file exists
// to catch. Every pattern begins `UPDATE\s+rules\s+SET`, so `UPDATE\s+rules` is
// implied by all of them, and the case-insensitive flag matches theirs. It is
// NOT a plain strings.Contains("UPDATE rules"): the patterns are (?i) and allow
// a newline between the words, so a lowercase or line-wrapped statement would be
// skipped by a literal check while the real patterns would have matched it.
var updateGateRe = regexp.MustCompile(`(?is)UPDATE\s+rules`)

func touchesRulesTable(sql string) bool { return updateGateRe.MatchString(sql) }

// Predicate forms beyond `= '…'`: migrations fix families of rules with LIKE and
// IN. 241/242/243 use them to repair broken detections, so treating them as
// no-ops means validating the pre-fix content — the drift this file exists to
// remove.
var (
	updateContentLikeRe = regexp.MustCompile(`(?is)UPDATE\s+rules\s+SET\s+([^$;]*?)content\s*=\s*\$\$` + dollarBody + `\$\$([^;]*?)WHERE\s+name\s+LIKE\s+'%([^%']*)%'`)
	updateContentInRe   = regexp.MustCompile(`(?is)UPDATE\s+rules\s+SET\s+([^$;]*?)content\s*=\s*\$\$` + dollarBody + `\$\$([^;]*?)WHERE\s+name\s+IN\s*\(([^)]*)\)`)
	updateReplaceLikeRe = regexp.MustCompile(`(?is)UPDATE\s+rules\s+SET\s+content\s*=\s*replace\(\s*content\s*,\s*'((?:[^']|'')*)'\s*,\s*'((?:[^']|'')*)'\s*\)([^;]*?)WHERE\s+name\s+LIKE\s+'%([^%']*)%'`)
	sqlStringRe         = regexp.MustCompile(`'((?:[^']|'')*)'`)
)

// unevaluablePredicates are UPDATE statements the harness deliberately does not
// model, with the reason. They select rows by columns DetectionRule does not
// carry (`source`, `curate_state`), so there is nothing to match against — the
// harness would have to model the curate pipeline's state machine to know which
// rules they hit.
//
// Listed rather than skipped silently: an unnamed exception is indistinguishable
// from a parser gap, and this file already shipped one of those.
var unevaluablePredicates = map[string]string{
	"292_curate_quarantine_invariant.sql": "bulk disable by source+curate_state; " +
		"DetectionRule models neither column",
}

// ruleColumnRe marks an UPDATE as relevant to this harness. A migration that
// backfills tenant_id across every row (027) changes nothing the rule engine
// evaluates, and demanding the extractor "understand" it would be the checker
// crying wolf — which gets checkers disabled.
var ruleColumnRe = regexp.MustCompile(`(?is)\b(content|enabled|severity|auto_isolate)\s*=`)

var (
	updateSeverityRe    = regexp.MustCompile(`(?is)\bseverity\s*=\s*(\d+)`)
	updateEnabledRe     = regexp.MustCompile(`(?is)\benabled\s*=\s*(true|false)`)
	updateAutoIsolateRe = regexp.MustCompile(`(?is)\bauto_isolate\s*=\s*(true|false)`)
)

// extractMigrationRules parses every `INSERT INTO rules` statement across the
// migration SQL files and returns the shipped detection rules. It resolves the
// column order per-statement (the migrations use 5 different orderings), so a
// rule's fields are mapped by column NAME, not position.
func extractMigrationRules() ([]*DetectionRule, error) {
	files, err := filepath.Glob(filepath.Join(migrationsDir, "*.sql"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)

	var out []*DetectionRule
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		sql := string(data)
		// Apply content UPDATEs after this file's inserts. Migrations are applied in
		// filename order and a rule is always inserted before it is patched, so
		// per-file ordering is enough; an UPDATE never precedes its own INSERT.
		defer func(sql string) {}(sql) // (ordering handled below; see applyUpdates)
		locs := insertHeaderRe.FindAllStringSubmatchIndex(sql, -1)
		for _, loc := range locs {
			cols := splitColumns(sql[loc[2]:loc[3]])
			mode := strings.ToUpper(sql[loc[4]:loc[5]])
			// Region begins right after the matched "...VALUES" / "...SELECT".
			region := sql[loc[1]:]
			var tuples [][]string
			if mode == "SELECT" {
				// SELECT form: one bare, un-parenthesised value list terminated by a
				// top-level WHERE / ON CONFLICT / RETURNING / ';'.
				tuples = [][]string{scanSelectValues(region)}
			} else {
				tuples = scanTuples(region)
			}
			for _, tup := range tuples {
				r, err := tupleToRule(cols, tup)
				if err != nil {
					return nil, fmt.Errorf("%s: %w", filepath.Base(f), err)
				}
				if r != nil {
					out = append(out, r)
				}
			}
		}
		applyContentUpdates(out, sql)
	}
	return out, nil
}

// applyContentUpdates rewrites the content of already-extracted rules from this
// file's `UPDATE rules SET content = …` statements, so the harness sees what the
// engine will actually load rather than the original insert text.
func applyContentUpdates(rules []*DetectionRule, sql string) {
	// Cheap gate before eight regex sweeps. Only ~20 of the 390 migrations touch
	// `rules` with an UPDATE, and the content patterns are not cheap: dollarBody's
	// `(?:[^$]|\$[^$])*` is a far larger automaton than the `(.*?)` it replaced,
	// and this function runs once per file per caller. Without this guard the
	// package went from 26s to 98s under -race and blew CI's 120s timeout — the
	// correctness fix was right, but paying for it on files that contain no
	// UPDATE at all was not.
	if !touchesRulesTable(sql) {
		return
	}
	applyNamedContentUpdates(rules, sql)
	for _, m := range updateContentRe.FindAllStringSubmatch(sql, -1) {
		assigns, content, name := m[1]+" "+m[3], m[2], m[4]
		for _, r := range rules {
			if r.Name != name {
				continue
			}
			r.Content = content
			if sm := updateSeverityRe.FindStringSubmatch(assigns); sm != nil {
				if v, err := strconv.Atoi(sm[1]); err == nil {
					r.Severity = v
				}
			}
			if em := updateEnabledRe.FindStringSubmatch(assigns); em != nil {
				r.Enabled = strings.EqualFold(em[1], "true")
			}
			if am := updateAutoIsolateRe.FindStringSubmatch(assigns); am != nil {
				r.AutoIsolate = strings.EqualFold(am[1], "true")
			}
		}
	}
	for _, m := range updateContentByIDRe.FindAllStringSubmatch(sql, -1) {
		assigns, content, id := m[1]+" "+m[3], m[2], m[4]
		for _, r := range rules {
			if r.ID == id {
				r.Content = content
				applyRuleFieldUpdates(r, assigns)
			}
		}
	}
	for _, m := range updateFieldsRe.FindAllStringSubmatch(sql, -1) {
		assigns, name := m[1], m[2]
		for _, r := range rules {
			if r.Name == name {
				applyRuleFieldUpdates(r, assigns)
			}
		}
	}
	for _, m := range updateFieldsByContentRe.FindAllStringSubmatch(sql, -1) {
		assigns, needle, excl := m[1], m[2], m[3]
		var not []string
		for _, e := range contentNotLikeRe.FindAllStringSubmatch(excl, -1) {
			not = append(not, e[1])
		}
		for _, r := range rules {
			if !strings.Contains(r.Content, needle) {
				continue
			}
			excluded := false
			for _, n := range not {
				if strings.Contains(r.Content, n) {
					excluded = true
					break
				}
			}
			if !excluded {
				applyRuleFieldUpdates(r, assigns)
			}
		}
	}
	for _, m := range updateFieldsByIDRe.FindAllStringSubmatch(sql, -1) {
		assigns, id := m[1], m[2]
		for _, r := range rules {
			if r.ID == id {
				applyRuleFieldUpdates(r, assigns)
			}
		}
	}
	for _, m := range updateContentLikeRe.FindAllStringSubmatch(sql, -1) {
		assigns, content, needle := m[1]+" "+m[3], m[2], m[4]
		for _, r := range rules {
			if strings.Contains(r.Name, needle) {
				r.Content = content
				applyRuleFieldUpdates(r, assigns)
			}
		}
	}
	for _, m := range updateContentInRe.FindAllStringSubmatch(sql, -1) {
		assigns, content := m[1]+" "+m[3], m[2]
		names := map[string]bool{}
		for _, q := range sqlStringRe.FindAllStringSubmatch(m[4], -1) {
			names[strings.ReplaceAll(q[1], "''", "'")] = true
		}
		for _, r := range rules {
			if names[r.Name] {
				r.Content = content
				applyRuleFieldUpdates(r, assigns)
			}
		}
	}
	// replace() edits apply to whatever the rule holds at this point in the
	// replay, so they must run after the wholesale rewrites above.
	for _, m := range updateReplaceRe.FindAllStringSubmatch(sql, -1) {
		from := strings.ReplaceAll(m[1], "''", "'")
		to := strings.ReplaceAll(m[2], "''", "'")
		key, val := strings.ToLower(m[4]), m[5]
		for _, r := range rules {
			if (key == "name" && r.Name == val) || (key == "id" && r.ID == val) {
				r.Content = strings.ReplaceAll(r.Content, from, to)
			}
		}
	}
	for _, m := range updateReplaceLikeRe.FindAllStringSubmatch(sql, -1) {
		from := strings.ReplaceAll(m[1], "''", "'")
		to := strings.ReplaceAll(m[2], "''", "'")
		needle := m[4]
		for _, r := range rules {
			if strings.Contains(r.Name, needle) {
				r.Content = strings.ReplaceAll(r.Content, from, to)
			}
		}
	}
}

// applyRuleFieldUpdates applies the flag columns an UPDATE assigns.
func applyRuleFieldUpdates(r *DetectionRule, assigns string) {
	if sm := updateSeverityRe.FindStringSubmatch(assigns); sm != nil {
		if v, err := strconv.Atoi(sm[1]); err == nil {
			r.Severity = v
		}
	}
	if em := updateEnabledRe.FindStringSubmatch(assigns); em != nil {
		r.Enabled = strings.EqualFold(em[1], "true")
	}
	if am := updateAutoIsolateRe.FindStringSubmatch(assigns); am != nil {
		r.AutoIsolate = strings.EqualFold(am[1], "true")
	}
}

// splitColumns splits a comma-separated column list, tolerating newlines.
func splitColumns(s string) []string {
	parts := strings.Split(s, ",")
	cols := make([]string, 0, len(parts))
	for _, p := range parts {
		cols = append(cols, strings.TrimSpace(p))
	}
	return cols
}

// scanTuples walks a `VALUES (…),(…),…;` region and returns each tuple's raw,
// top-level column tokens. It respects single-quote strings (with ” escaping),
// dollar-quoted strings ($tag$…$tag$), parenthesis depth (so gen_random_uuid()
// does not split a tuple) and bracket depth (so ARRAY['a','b'] commas do not
// split a column). Line comments (-- …) between tuples are skipped. It stops at
// the first top-level ';'.
func scanTuples(s string) [][]string {
	var tuples [][]string
	i, n := 0, len(s)
	for i < n {
		// Skip inter-tuple whitespace, commas and line comments.
		for i < n {
			c := s[i]
			if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ',' {
				i++
				continue
			}
			if c == '-' && i+1 < n && s[i+1] == '-' {
				for i < n && s[i] != '\n' {
					i++
				}
				continue
			}
			break
		}
		if i >= n || s[i] == ';' {
			break
		}
		if s[i] != '(' {
			// Not a tuple start (e.g. trailing keyword); stop scanning this region.
			break
		}
		i++ // consume '('
		vals, next := scanTupleValues(s, i)
		tuples = append(tuples, vals)
		i = next
	}
	return tuples
}

// scanSelectValues parses the bare, un-parenthesised value list of an
// `INSERT INTO rules (...) SELECT v1, v2, … [WHERE …|ON CONFLICT …|RETURNING …|;]`
// statement. It splits on top-level commas (respecting quotes/dollar-quotes and
// paren/bracket depth) and stops at the first top-level SQL tail clause keyword
// or ';'. Same quoting rules as scanTupleValues.
func scanSelectValues(s string) []string {
	n := len(s)
	var vals []string
	var cur strings.Builder
	depth, bracket := 0, 0
	flush := func() { vals = append(vals, strings.TrimSpace(cur.String())); cur.Reset() }
	// isTailKeyword reports whether a top-level clause keyword begins at position i.
	isTailKeyword := func(i int) bool {
		if depth != 0 || bracket != 0 {
			return false
		}
		up := strings.ToUpper(s[i:min(i+12, n)])
		for _, kw := range []string{"WHERE ", "WHERE\n", "WHERE\t", "ON CONFLICT", "RETURNING"} {
			if strings.HasPrefix(up, kw) {
				return true
			}
		}
		return false
	}
	for i := 0; i < n; {
		c := s[i]
		switch {
		case c == '\'':
			cur.WriteByte(c)
			i++
			for i < n {
				if s[i] == '\'' {
					if i+1 < n && s[i+1] == '\'' {
						cur.WriteString("''")
						i += 2
						continue
					}
					cur.WriteByte('\'')
					i++
					break
				}
				cur.WriteByte(s[i])
				i++
			}
		case c == '$':
			tagEnd := strings.IndexByte(s[i+1:], '$')
			if tagEnd < 0 {
				cur.WriteByte(c)
				i++
				continue
			}
			delim := s[i : i+1+tagEnd+1]
			cur.WriteString(delim)
			i += len(delim)
			if close := strings.Index(s[i:], delim); close >= 0 {
				cur.WriteString(s[i : i+close+len(delim)])
				i += close + len(delim)
			} else {
				i = n
			}
		case c == '-' && i+1 < n && s[i+1] == '-':
			for i < n && s[i] != '\n' {
				i++
			}
		case c == ';' && depth == 0 && bracket == 0:
			flush()
			return vals
		case isTailKeyword(i):
			flush()
			return vals
		case c == '(':
			depth++
			cur.WriteByte(c)
			i++
		case c == ')':
			depth--
			cur.WriteByte(c)
			i++
		case c == '[':
			bracket++
			cur.WriteByte(c)
			i++
		case c == ']':
			bracket--
			cur.WriteByte(c)
			i++
		case c == ',' && depth == 0 && bracket == 0:
			flush()
			i++
		default:
			cur.WriteByte(c)
			i++
		}
	}
	flush()
	return vals
}

// scanTupleValues parses the interior of one tuple starting at position i (just
// past the opening '('). It returns the top-level column tokens and the position
// just past the closing ')'.
func scanTupleValues(s string, i int) ([]string, int) {
	n := len(s)
	var vals []string
	var cur strings.Builder
	depth, bracket := 0, 0
	flush := func() {
		vals = append(vals, strings.TrimSpace(cur.String()))
		cur.Reset()
	}
	for i < n {
		c := s[i]
		switch {
		case c == '\'':
			// Single-quoted string with '' escape.
			cur.WriteByte(c)
			i++
			for i < n {
				if s[i] == '\'' {
					if i+1 < n && s[i+1] == '\'' {
						cur.WriteString("''")
						i += 2
						continue
					}
					cur.WriteByte('\'')
					i++
					break
				}
				cur.WriteByte(s[i])
				i++
			}
		case c == '$':
			// Dollar-quoted string: $tag$ … $tag$ (tag may be empty).
			tagEnd := strings.IndexByte(s[i+1:], '$')
			if tagEnd < 0 {
				cur.WriteByte(c)
				i++
				continue
			}
			delim := s[i : i+1+tagEnd+1] // includes both $
			cur.WriteString(delim)
			i += len(delim)
			if close := strings.Index(s[i:], delim); close >= 0 {
				cur.WriteString(s[i : i+close+len(delim)])
				i += close + len(delim)
			} else {
				i = n
			}
		case c == '-' && i+1 < n && s[i+1] == '-':
			// Line comment inside the tuple (defensive) — skip to EOL.
			for i < n && s[i] != '\n' {
				i++
			}
		case c == '(':
			depth++
			cur.WriteByte(c)
			i++
		case c == ')':
			if depth == 0 {
				flush()
				i++ // consume closing ')'
				return vals, i
			}
			depth--
			cur.WriteByte(c)
			i++
		case c == '[':
			bracket++
			cur.WriteByte(c)
			i++
		case c == ']':
			bracket--
			cur.WriteByte(c)
			i++
		case c == ',' && depth == 0 && bracket == 0:
			flush()
			i++
		default:
			cur.WriteByte(c)
			i++
		}
	}
	flush()
	return vals, i
}

// tupleToRule maps a tuple's raw column tokens to a DetectionRule using the
// statement's column names. Returns nil (skip) if the tuple has no usable
// content column.
func tupleToRule(cols, vals []string) (*DetectionRule, error) {
	if len(vals) != len(cols) {
		return nil, fmt.Errorf("column/value count mismatch: %d cols, %d vals (%v)", len(cols), len(vals), vals)
	}
	r := &DetectionRule{Enabled: true} // default enabled unless an `enabled` column says otherwise
	sawContent := false
	for idx, col := range cols {
		raw := vals[idx]
		switch strings.ToLower(col) {
		case "id":
			r.ID = unquoteScalar(raw)
		case "name":
			r.Name = unquoteScalar(raw)
		case "type":
			r.Type = unquoteScalar(raw)
		case "platform":
			r.Platform = parseArrayLiteral(raw)
		case "severity":
			// best-effort; not needed for match assertions
		case "content":
			r.Content = unquoteScalar(raw)
			sawContent = true
		case "enabled":
			r.Enabled = strings.EqualFold(strings.TrimSpace(raw), "true")
		case "auto_isolate":
			r.AutoIsolate = strings.EqualFold(strings.TrimSpace(raw), "true")
		case "auto_kill":
			r.AutoKill = strings.EqualFold(strings.TrimSpace(raw), "true")
		case "mitre_tags":
			r.MITRETags = parseArrayLiteral(raw)
		}
	}
	if r.ID == "" {
		r.ID = r.Name
	}
	if !sawContent {
		return nil, nil
	}
	return r, nil
}

// unquoteScalar strips $$…$$ / $tag$…$tag$ dollar quoting or '…' single quoting
// (unescaping ”) from a scalar SQL literal. Barewords (NOW(), NULL) pass through.
func unquoteScalar(raw string) string {
	s := strings.TrimSpace(raw)
	if strings.HasPrefix(s, "$") {
		if tagEnd := strings.IndexByte(s[1:], '$'); tagEnd >= 0 {
			delim := s[:1+tagEnd+1]
			inner := strings.TrimPrefix(s, delim)
			inner = strings.TrimSuffix(inner, delim)
			return inner
		}
	}
	if strings.HasPrefix(s, "'") && strings.HasSuffix(s, "'") && len(s) >= 2 {
		return strings.ReplaceAll(s[1:len(s)-1], "''", "'")
	}
	return s
}

// parseArrayLiteral extracts the string elements of an ARRAY['a','b'] literal.
func parseArrayLiteral(raw string) []string {
	s := strings.TrimSpace(raw)
	l := strings.Index(s, "[")
	r := strings.LastIndex(s, "]")
	if l < 0 || r < 0 || r <= l {
		return nil
	}
	inner := s[l+1 : r]
	var out []string
	for _, part := range strings.Split(inner, ",") {
		p := strings.TrimSpace(part)
		p = strings.Trim(p, "'")
		p = strings.ReplaceAll(p, "''", "'")
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// Every `UPDATE rules SET … WHERE name = '…'` in the migrations must be one the
// extractor actually understood.
//
// This is the generalisation of the bug that prompted it. updateContentRe used
// to require `SET content = $$…$$` literally, so migration 373's
// `SET severity = 4, content = $$…$$` matched nothing — and nothing said so. The
// harness reported the rule's ORIGINAL insert text while production ran the
// updated one, which is exactly the drift this whole file exists to eliminate.
//
// A parser that quietly skips input it does not recognise is worse than one that
// fails: the first looks like coverage.
func TestEveryUpdateRulesStatementIsUnderstood(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(migrationsDir, "*.sql"))
	if err != nil {
		t.Fatalf("glob migrations: %v", err)
	}
	sort.Strings(files)

	var seen, understood int
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		sql := string(b)

		if !touchesRulesTable(sql) {
			continue
		}
		claimed := map[int]bool{}
		for _, re := range []*regexp.Regexp{
			updateContentRe, updateContentNamedRe, updateContentByIDRe, updateContentLikeRe, updateContentInRe,
			updateFieldsRe, updateFieldsByIDRe, updateFieldsByContentRe,
			updateReplaceRe, updateReplaceLikeRe,
		} {
			for _, loc := range re.FindAllStringIndex(sql, -1) {
				claimed[loc[0]] = true
			}
		}
		starts := updateStmtStartRe.FindAllStringIndex(sql, -1)
		for i, loc := range starts {
			// Bound the statement at the NEXT `UPDATE rules SET`. A fixed-width
			// window bleeds into the following statement and inherits its
			// columns, which made a curate_state bulk update look like a content
			// change. The checker was wrong about its own scope.
			end := len(sql)
			if i+1 < len(starts) {
				end = starts[i+1][0]
			}
			// Only statements that ASSIGN a column the rule engine reads are in
			// scope. Judge the SET clause alone: a curate_state bulk update
			// whose WHERE reads `enabled = TRUE` sets nothing this harness
			// models, and matching on the predicate made the checker claim a
			// statement it had no business claiming.
			if !ruleColumnRe.MatchString(setClauseOf(sql[loc[0]:end])) {
				continue
			}
			seen++
			if claimed[loc[0]] {
				understood++
				continue
			}
			if why, ok := unevaluablePredicates[filepath.Base(f)]; ok {
				t.Logf("%s: not modelled by design — %s", filepath.Base(f), why)
				continue
			}
			if end > loc[0]+160 {
				end = loc[0] + 160
			}
			t.Errorf("%s: an `UPDATE rules SET` at offset %d was not parsed by either pattern.\n"+
				"  %s…\n"+
				"  The extractor would silently report this rule's pre-update state while "+
				"production runs the updated one. Extend the patterns rather than leaving the "+
				"statement unhandled — a parser that skips input it does not recognise looks "+
				"like coverage.", filepath.Base(f), loc[0], strings.TrimSpace(sql[loc[0]:end]))
		}
	}
	if seen == 0 {
		t.Fatal("no `UPDATE rules SET` statements found at all — the scan is broken and this " +
			"test would pass vacuously")
	}
	t.Logf("understood %d/%d UPDATE rules statements", understood, seen)
}

// setClauseOf returns the assignment part of an UPDATE — everything between SET
// and the WHERE that ends it — with dollar-quoted literals removed so a `WHERE`
// inside rule YAML cannot truncate it early.
func setClauseOf(stmt string) string {
	var b strings.Builder
	for i := 0; i < len(stmt); {
		if strings.HasPrefix(stmt[i:], "$$") {
			if j := strings.Index(stmt[i+2:], "$$"); j >= 0 {
				i += 2 + j + 2
				continue
			}
			break
		}
		b.WriteByte(stmt[i])
		i++
	}
	out := b.String()
	// The delimiter is whitespace-WHERE-whitespace, not " WHERE " — migrations
	// put the WHERE on its own line, and assuming a space left the predicate in
	// the slice, where `enabled = TRUE` masqueraded as an assignment.
	if m := whereDelimRe.FindStringIndex(out); m != nil {
		out = out[:m[0]]
	}
	return out
}

var whereDelimRe = regexp.MustCompile(`(?is)\sWHERE\s`)

// The fast-path gate must never hide a statement the real patterns would match.
//
// touchesRulesTable exists purely for speed: without it the eight UPDATE
// patterns sweep all 390 migrations and the package went from 26s to 98s under
// -race, overrunning CI's 120s timeout. A pre-filter that is even slightly
// narrower than what it guards turns that speedup into silent under-reporting —
// which is the same defect class as the parser gaps this file was written to
// close, just moved one layer out.
//
// Asserted against the real corpus rather than argued from the regex source.
func TestUpdateGateIsASupersetOfEveryPattern(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(migrationsDir, "*.sql"))
	if err != nil {
		t.Fatalf("glob migrations: %v", err)
	}
	patterns := []*regexp.Regexp{
		updateContentRe, updateContentNamedRe, updateContentByIDRe, updateContentLikeRe, updateContentInRe,
		updateFieldsRe, updateFieldsByIDRe, updateFieldsByContentRe,
		updateReplaceRe, updateReplaceLikeRe,
		updateStmtStartRe,
	}

	var gated int
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		sql := string(b)
		open := touchesRulesTable(sql)
		if open {
			gated++
			continue
		}
		for i, re := range patterns {
			if re.MatchString(sql) {
				t.Errorf("%s: pattern %d matches but touchesRulesTable said no. The gate is "+
					"narrower than what it guards, so this file's UPDATE statements are being "+
					"skipped entirely — silently, and only for performance.",
					filepath.Base(f), i)
			}
		}
	}
	if gated == 0 {
		t.Fatal("the gate opened for no migration at all — either the scan is broken or the " +
			"gate is inverted; this test would pass vacuously")
	}
	t.Logf("gate opened for %d of %d migrations", gated, len(files))
}
