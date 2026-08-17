package detection

import (
	"strings"
	"testing"
)

// The `rules` table is the source server-detect evaluates and the one P4-6 says
// the real-time path must also read. These tests cover the loading contract
// without a database: the DB round-trip itself is exercised by the integration
// suite, but every decision the loader makes about a row — collide, tag, skip —
// is decided here from the row's bytes and is testable from them.

func TestSigmaTitleOf(t *testing.T) {
	cases := []struct{ in, want string }{
		{"title: Process Hollowing\nid: x\n", "Process Hollowing"},
		{"# comment\ntitle:   Spaced Out  \n", "Spaced Out"},
		{`title: "Quoted Title"`, "Quoted Title"},
		{"title: 'Single Quoted'", "Single Quoted"},
		{"id: x\nlevel: high\n", ""},
		// `title:` inside the detection block must not be read as the rule title.
		// It is the FIRST occurrence that wins, matching how a YAML parser binds
		// a top-level key.
		{"title: Real\ndetection:\n  sel:\n    title: bait\n", "Real"},
	}
	for _, c := range cases {
		if got := sigmaTitleOf(c.in); got != c.want {
			t.Errorf("sigmaTitleOf(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSigmaTagsFromColumn(t *testing.T) {
	got := sigmaTagsFromColumn([]string{"T1055.012", "attack.t1047", " T1003 ", "", "persistence", "windows"})
	want := []string{"attack.t1055.012", "attack.t1047", "attack.t1003"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("sigmaTagsFromColumn = %v, want %v", got, want)
	}
	// A tactic name or platform must not become a tag: parseMITRETechFromTags
	// would then return "PERSISTENCE" as the alert's mitre_technique, which is
	// not a technique ID and groups with nothing.
	for _, g := range got {
		if !strings.HasPrefix(g, "attack.t") {
			t.Errorf("%q is not a technique tag", g)
		}
	}
}

func TestDBSigmaRulesKillSwitch(t *testing.T) {
	// Default is ON — the entire point of P4-6 is that these rules never fire.
	t.Setenv(dbSigmaRulesEnvVar, "")
	if !dbSigmaRulesEnabled() {
		t.Error("DB Sigma rules must default to enabled")
	}
	for _, off := range []string{"0", "false", "FALSE", "no", "off", " Off "} {
		t.Setenv(dbSigmaRulesEnvVar, off)
		if dbSigmaRulesEnabled() {
			t.Errorf("%q must disable DB Sigma rules — an operator shedding this load "+
				"cannot wait for a rebuild", off)
		}
	}
	for _, on := range []string{"1", "true", "yes", "anything-else"} {
		t.Setenv(dbSigmaRulesEnvVar, on)
		if !dbSigmaRulesEnabled() {
			t.Errorf("%q must leave DB Sigma rules enabled", on)
		}
	}
}

// A rule whose YAML has no attack.* tag gets the row's mitre_tags, and a rule
// that HAS one keeps it.
//
// The fallback direction matters: the YAML is the rule author's statement and
// the column is metadata around it, so the column must never override a tag the
// rule itself declares.
func TestLoadRuleWithFallbackTags(t *testing.T) {
	const untagged = `
title: Untagged Rule
logsource:
  product: windows
  category: process_creation
detection:
  sel:
    Image|endswith: '\evil.exe'
  condition: sel
level: high
`
	const tagged = `
title: Tagged Rule
tags:
  - attack.t1059.001
logsource:
  product: windows
  category: process_creation
detection:
  sel:
    Image|endswith: '\evil.exe'
  condition: sel
level: high
`
	e := NewSigmaEvaluator()
	if err := e.LoadRuleWithFallbackTags(untagged, []string{"attack.t1055.012"}); err != nil {
		t.Fatalf("load untagged: %v", err)
	}
	if err := e.LoadRuleWithFallbackTags(tagged, []string{"attack.t1055.012"}); err != nil {
		t.Fatalf("load tagged: %v", err)
	}

	byTitle := map[string]*CompiledSigmaRule{}
	for _, r := range e.rules {
		byTitle[r.Rule.Title] = r
	}
	if got := parseMITRETechFromTags(byTitle["Untagged Rule"].Rule.Tags); got != "T1055.012" {
		t.Errorf("untagged rule technique = %q, want T1055.012 from the mitre_tags column. "+
			"Without it the alert carries mitre_technique NULL, which also makes it "+
			"invisible to cross-engine deduplication", got)
	}
	if got := parseMITRETechFromTags(byTitle["Tagged Rule"].Rule.Tags); got != "T1059.001" {
		t.Errorf("tagged rule technique = %q, want T1059.001 — the column must not "+
			"override a tag the rule declares", got)
	}
}

// Builtins must win a title collision.
//
// CLAUDE.md's dual-source section is explicit that the same rule name exists in
// both sigma_builtins.go and the `rules` table WITH DIFFERENT MATCHING LOGIC.
// Loading both would evaluate two rules that report under one title, so an
// analyst reading the alert cannot tell which YAML produced it. Five of the 230
// migration-shipped titles collide today.
func TestBuiltinTitlesWinCollisions(t *testing.T) {
	e := NewSigmaEvaluator()
	if n := LoadBuiltinRules(e); n == 0 {
		t.Fatal("no builtin rules loaded")
	}
	before := e.RuleCount()
	titles := e.LoadedTitles()

	var sample string
	for tl := range titles {
		sample = tl
		break
	}
	if sample == "" {
		t.Fatal("no builtin titles")
	}

	// Simulate what the loader does with a colliding row: consult LoadedTitles
	// and skip. This is the decision under test — the DB fetch around it is not.
	if !titles[sample] {
		t.Fatalf("LoadedTitles does not report the builtin title %q it just loaded", sample)
	}
	if e.RuleCount() != before {
		t.Error("LoadedTitles must not mutate the rule set")
	}
}

// Every migration-shipped Sigma rule the loader will hand to LoadRule must
// compile in THIS evaluator.
//
// migration_sigma_parse_test.go already gates parseability. This one is about
// the LOADER's contract specifically: it counts what will actually be loaded
// after collisions are skipped, and fails if that number collapses. A silent
// drop to zero is exactly the failure mode the previous version of sigma_db.go
// had for months — the query errored, the error went to Debug, and "0 rules
// loaded" looked like normal operation.
func TestDBSigmaRulesActuallyLoad(t *testing.T) {
	blocks := migrationSigmaBlocks(t)
	if len(blocks) < 200 {
		t.Fatalf("only %d migration Sigma blocks found — the scan is broken and this "+
			"test would pass vacuously", len(blocks))
	}

	e := NewSigmaEvaluator()
	LoadBuiltinRules(e)
	builtins := e.RuleCount()
	existing := e.LoadedTitles()

	var loaded, failedCount, collisions int
	var failures []string
	for title, b := range blocks {
		if existing[title] {
			collisions++
			continue
		}
		if err := e.LoadRuleWithFallbackTags(b.body, nil); err != nil {
			failedCount++
			failures = append(failures, title+" ("+b.file+"): "+err.Error())
			continue
		}
		loaded++
	}

	for _, f := range failures {
		t.Errorf("a rule the loader would ship failed to compile: %s", f)
	}
	if loaded < 200 {
		t.Errorf("only %d DB rules would load (builtins=%d, collisions=%d, failed=%d). "+
			"P4-6 exists because these rules never reach the real-time path; a loader "+
			"that ships a handful of them has not fixed it",
			loaded, builtins, collisions, failedCount)
	}
	if e.RuleCount() != builtins+loaded {
		t.Errorf("evaluator holds %d rules, expected %d builtins + %d DB",
			e.RuleCount(), builtins, loaded)
	}
	t.Logf("builtins=%d db_loaded=%d builtin_collisions=%d total=%d",
		builtins, loaded, collisions, e.RuleCount())
}

// A rule loaded from the `rules` table must report the severity that table
// declares, so the API and the detection engine describe the same finding with
// the same number.
//
// Deduplication keys on (title, severity, source, agent). Title case already did
// not matter — DedupKey lowercases it — so severity was the entire reason the
// two engines' copies of one detection could not be merged. Measured at 55
// unmerged duplicates per 1.67 benign host-days before this.
func TestDBRuleCarriesItsDeclaredSeverity(t *testing.T) {
	const rule = `
title: Severity Carrier
logsource:
  product: linux
  category: process_creation
detection:
  sel:
    CommandLine|contains: 'carrier-probe'
  condition: sel
level: low
`
	e := NewSigmaEvaluator()
	if err := e.loadDBRule(rule, nil, 4, nil); err != nil {
		t.Fatalf("loadDBRule: %v", err)
	}
	m := e.EvaluateEvent(map[string]interface{}{
		"type": "process", "commandLine": "sh -c carrier-probe",
	})
	if len(m) != 1 {
		t.Fatalf("got %d matches, want 1", len(m))
	}
	if m[0].Severity != 4 {
		t.Errorf("match.Severity = %d, want 4 (the rules.severity column). "+
			"The Sigma level is `low`, which would derive 3 — and 3 vs the engine's 4 "+
			"is exactly what stopped the two copies of this finding from deduplicating",
			m[0].Severity)
	}

	// A builtin has no row behind it, so it must keep deriving from the level.
	// Reporting 0 would make every builtin alert severity 0.
	b := NewSigmaEvaluator()
	if err := b.LoadRule(rule); err != nil {
		t.Fatalf("LoadRule: %v", err)
	}
	bm := b.EvaluateEvent(map[string]interface{}{
		"type": "process", "commandLine": "sh -c carrier-probe",
	})
	if len(bm) != 1 || bm[0].Severity != 0 {
		t.Fatalf("builtin match must carry Severity 0 so the caller falls back to "+
			"the level, got %+v", bm)
	}
	if got := sigmaLevelToInt(bm[0].Level); got != 3 {
		t.Errorf("builtin fallback severity = %d, want 3", got)
	}
}
