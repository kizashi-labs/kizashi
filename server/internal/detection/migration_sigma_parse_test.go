package detection

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Sigma content seeded into the `rules` table by migrations must parse in THIS
// evaluator — the one server-api's AlertPipeline uses.
//
// The hole this closes: `rules/sigma/**/*.yml` on disk is already syntax-gated,
// because cmd/validate-rules runs those files through the production
// SigmaEvaluator on every push (ci.yml's rules-validate job). Rule content that
// lives inside migration SQL never went through it. Nothing read those bytes
// with this parser until someone did it by hand on 2026-08-03 and found four
// rules with a duplicate `CommandLine|contains` key in one selection.
//
// Duplicate mapping keys are invalid YAML. yaml.v3 (this evaluator) rejects the
// document outright; sigma-go (server-detect's engine) accepts it and takes the
// LAST occurrence. So those four rules were, at the same time:
//
//   - non-existent in server-api, because the rule failed to load
//   - stripped of their discriminating condition in server-detect, because the
//     first key — always the one naming the binary — was the one discarded
//
// The second half is what showed up in the 2026-08-03 FP soak: two of the four
// produced 29 of the 439 false positives. Fixed by migration 371.
//
// This is deliberately a parse gate, not a semantic one. It cannot tell whether
// a rule means what its author intended; it can tell whether both engines will
// agree that the rule exists at all.

var (
	ruleTitleRe = regexp.MustCompile(`(?m)^title:\s*(.*)$`)
	// Opening delimiter of a Postgres dollar-quoted string: $$ or $tag$.
	dollarOpenRe = regexp.MustCompile(`\$[A-Za-z_][A-Za-z_0-9]*\$|\$\$`)
)

// dollarQuotedBodies returns the contents of every dollar-quoted string in sql.
//
// This started life as the regexp `\$\$(.*?)\$\$`, which silently saw only the
// untagged form. Postgres also allows a TAG between the dollars, and migration
// 014 uses $SIGMA$ — so its five Sigma rules, including the WMI lateral-movement
// rule, were never once handed to the parser this file exists to run them
// through. The gate reported green over a file it could not see: the same shape
// as the inert-rule bugs it was written to catch, in the checker itself.
//
// It cannot go back to being one regexp. Matching a tagged quote requires
// asserting that the closing delimiter equals the opening one, and RE2 has no
// backreferences. So the tag is captured and the closer is found by index.
func dollarQuotedBodies(sql string) []string {
	var out []string
	for i := 0; i < len(sql); {
		loc := dollarOpenRe.FindStringIndex(sql[i:])
		if loc == nil {
			break
		}
		start, end := i+loc[0], i+loc[1]
		delim := sql[start:end]
		rest := sql[end:]
		n := strings.Index(rest, delim)
		if n < 0 {
			// Unterminated: nothing sensible to extract, and skipping only this
			// delimiter would rescan the body as if it were SQL.
			break
		}
		out = append(out, rest[:n])
		i = end + n + len(delim)
	}
	return out
}

// sigmaBlock is one rule's content and the migration it last came from.
type sigmaBlock struct {
	file string
	body string
}

// migrationSigmaBlocks returns the Sigma rule content the database ends up with,
// keyed by rule title.
//
// Migrations are replayed in filename order and a later definition of the same
// title REPLACES an earlier one, because that is what the database does: 019
// inserts a rule, 371 UPDATEs it, and only 371's content survives. Keeping both
// would make this test report a defect that no longer exists in any running
// system — and a checker that reports fixed bugs gets disabled just as fast as
// one that misses real ones.
//
// Matching on `detection:` + `condition:` rather than on the surrounding SQL is
// intentional: rules arrive via INSERT in some migrations and UPDATE in others,
// and a checker that only understood INSERT would go quiet exactly when a rule
// is being rewritten.
func migrationSigmaBlocks(t *testing.T) map[string]sigmaBlock {
	t.Helper()
	dir := filepath.Join("..", "..", "migrations")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read migrations: %v", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	out := map[string]sigmaBlock{}
	for _, name := range names {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		for _, body := range dollarQuotedBodies(string(b)) {
			if !strings.Contains(body, "detection:") || !strings.Contains(body, "condition:") {
				continue
			}
			title := "(untitled)"
			if tm := ruleTitleRe.FindStringSubmatch(body); tm != nil {
				title = strings.TrimSpace(tm[1])
			}
			out[title] = sigmaBlock{file: name, body: body}
		}
	}
	return out
}

func TestMigrationSigmaRulesParseInProductionEvaluator(t *testing.T) {
	blocks := migrationSigmaBlocks(t)
	if len(blocks) < 100 {
		t.Fatalf("only %d Sigma blocks extracted from migrations — the extractor is broken "+
			"and this test would pass vacuously", len(blocks))
	}

	keys := make([]string, 0, len(blocks))
	for k := range blocks {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		blk := blocks[k]
		if err := NewSigmaEvaluator().LoadRule(blk.body); err != nil {
			t.Errorf("%s (%s) does not parse in the api-server evaluator: %v\n"+
				"  server-detect's sigma-go may still accept it, which is worse than a clean "+
				"failure: the rule is absent from one engine and silently altered in the other "+
				"(duplicate YAML keys take the LAST value, dropping the first condition)",
				k, blk.file, err)
		}
	}
}

// The extractor's own blind spot, made loud.
//
// `$SIGMA$`-tagged dollar quoting is used by exactly one migration today, and
// the previous `\$\$(.*?)\$\$` extractor skipped it entirely — so 014's rules
// were exempt from the parse gate above without anything saying so. The count
// guard did not help: 100+ rules still came through the untagged files.
//
// Naming the tagged form here means a future rewrite of dollarQuotedBodies that
// loses it fails, instead of quietly shrinking the gate's reach again.
func TestMigrationSigmaExtractorReadsTaggedDollarQuotes(t *testing.T) {
	blocks := migrationSigmaBlocks(t)
	// From migration 014, which is $SIGMA$-quoted throughout.
	for _, title := range []string{
		"WMI Remote Command Execution",
		"Lateral Movement via RDP",
	} {
		blk, ok := blocks[title]
		if !ok {
			t.Errorf("%q was not extracted — dollarQuotedBodies has stopped reading $tag$-quoted "+
				"strings, so migration 014's rules are silently exempt from the parse gate", title)
			continue
		}
		if blk.file != "014_lateral_movement_rules.sql" {
			t.Errorf("%q came from %s, expected 014_lateral_movement_rules.sql", title, blk.file)
		}
	}
}

// The four rules migration 371 repaired. Asserting on the repaired shape keeps a
// future edit from reintroducing the duplicate key — the parse gate above would
// catch that too, but this names the specific rules and what they must require,
// so a regression reads as "the tar binary check is gone" rather than as a YAML
// error.
func TestMigration371RulesRequireTheirDiscriminatingToken(t *testing.T) {
	blocks := migrationSigmaBlocks(t)

	for _, tc := range []struct {
		title  string
		needle string // the condition token that must survive
	}{
		{"Archive Collected Data via Compression Utility (Linux)", "tar_bin and tar_create"},
		{"Data Exfiltration via curl/wget Upload (Linux)", "curl_bin and curl_upload"},
		{"Suspicious chmod of Executable in /tmp", "chmod_bin and mode_bits and staging_dir"},
		{"Suspicious wscript/cscript Execution", "script_host and script_ext and user_writable"},
	} {
		blk, ok := blocks[tc.title]
		if !ok {
			t.Errorf("no migration defines %q any more", tc.title)
			continue
		}
		// The winning definition must be the repaired one. If an even later
		// migration rewrites these, it has to keep the split selections.
		if !strings.Contains(blk.body, tc.needle) {
			t.Errorf("%s (winning definition: %s): condition no longer requires %q — the "+
				"discriminating token has been dropped again, which is what made this rule "+
				"fire on unrelated command lines", tc.title, blk.file, tc.needle)
		}
		if err := NewSigmaEvaluator().LoadRule(blk.body); err != nil {
			t.Errorf("%s (%s): %v", tc.title, blk.file, err)
		}
	}
}
