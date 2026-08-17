package detectionmetrics

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Both MITRE roll-ups grouped by `rules.mitre_tactic`, and the technique listing
// also selected `rules.mitre_technique`. Neither column exists, so both queries
// were rejected with 42703 and the ATT&CK coverage panel was permanently empty —
// which reads as "this deployment detects nothing", not as "the query failed".
//
// This was not a rename. The ATT&CK data is in `mitre_tags` (text[]), holding
// technique IDs, with no tactic anywhere in the table. The tactic is derived in
// Go from detection.TacticForTechnique, which is the same mapping the kill-chain
// correlator uses, so the two cannot disagree about which tactic a technique
// belongs to.
//
// The load-bearing detail is that one rule can carry several techniques. Summing
// technique occurrences would count such a rule once per technique, inflating
// every tactic it touches — so the fold counts distinct rule ids per tactic,
// which is what the original COUNT(DISTINCT r.id) meant.

func mitrePool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping DB integration tests")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// seedRule inserts one enabled rule carrying the given technique IDs.
func seedRule(t *testing.T, pool *pgxpool.Pool, name string, techniques ...string) {
	t.Helper()
	id := uuid.NewString()
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO rules (id, name, type, severity, content, enabled, mitre_tags)
		VALUES ($1::uuid, $2, 'sigma', 5, 'fixture', true, $3)`,
		id, name, techniques); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM rules WHERE id=$1::uuid`, id)
	})
}

// The headline: the coverage panel names the tactics the enabled rules cover.
func TestMITRECoverageDerivesTacticsFromTheTechniqueTags(t *testing.T) {
	pool := mitrePool(t)
	ctx := context.Background()

	marker := uuid.NewString()[:8]
	// T1003 = OS credential dumping (credential-access).
	// T1003.001 is a sub-technique of it, so it folds to the same tactic.
	// T1021 = remote services (lateral-movement).
	seedRule(t, pool, "mitre-fixture-a-"+marker, "T1003")
	seedRule(t, pool, "mitre-fixture-b-"+marker, "T1003.001")
	seedRule(t, pool, "mitre-fixture-c-"+marker, "T1021")

	coverage, err := NewTracker(pool).GetMITRECoverage(ctx)
	if err != nil {
		t.Fatalf("GetMITRECoverage: %v", err)
	}
	if len(coverage) == 0 {
		t.Fatal("ATT&CK カバレッジが空です。rules に mitre_tactic / mitre_technique " +
			"という列は無く、クエリが 42703 で拒否されると" +
			"「何も検知していない」ように見えます")
	}

	// The table is shared, so these are membership checks on this fixture's own
	// techniques rather than an exact-set comparison.
	for _, want := range []struct{ tactic, technique string }{
		{"credential-access", "T1003"},
		{"credential-access", "T1003.001"},
		{"lateral-movement", "T1021"},
	} {
		found := false
		for _, got := range coverage[want.tactic] {
			if got == want.technique {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s が %s に含まれません: %v。"+
				"サブテクニックは親テクニックの戦術に寄せる必要があります",
				want.technique, want.tactic, coverage[want.tactic])
		}
	}

	// The list is "which techniques are covered", so a technique several rules
	// detect must appear once. Membership alone cannot see this — dropping the
	// deduplication passed the checks above — and the duplicates are what a
	// "covered techniques" count is read off.
	for tactic, techniques := range coverage {
		seen := map[string]bool{}
		for _, tech := range techniques {
			if seen[tech] {
				t.Errorf("%s に %s が重複しています: %v。"+
					"同じテクニックを複数のルールが検知していても"+
					"カバー済みテクニックは1件です", tactic, tech, techniques)
				break
			}
			seen[tech] = true
		}
	}
}

// A rule carrying several techniques of the same tactic is one rule, not
// several. Counting technique occurrences instead of rules is the mistake that
// makes a handful of broad rules look like full coverage.
func TestARuleWithSeveralTechniquesIsCountedOncePerTactic(t *testing.T) {
	pool := mitrePool(t)
	ctx := context.Background()

	marker := uuid.NewString()[:8]

	before, err := NewTracker(pool).Calculate(ctx, "24h")
	if err != nil {
		t.Fatalf("Calculate: %v", err)
	}
	baseline := before.MITRECoverage["credential-access"]

	// Three credential-access techniques, one rule.
	seedRule(t, pool, "mitre-multi-"+marker, "T1003", "T1003.002", "T1552")

	after, err := NewTracker(pool).Calculate(ctx, "24h")
	if err != nil {
		t.Fatalf("Calculate: %v", err)
	}
	if delta := after.MITRECoverage["credential-access"] - baseline; delta != 1 {
		t.Errorf("credential-access のルール数が %d 増えました (1を期待)。"+
			"1つのルールが3つのテクニックを持つ場合でもルールは1件です — "+
			"テクニックの出現数を数えると戦術ごとに水増しされます", delta)
	}
}

// "unknown" is where an unmapped technique lands. It is not one of the 14 ATT&CK
// tactics, so it must not raise the coverage figure — otherwise a single rule
// tagged with a technique the mapping does not know inflates coverage by 1/14.
func TestAnUnmappedTechniqueDoesNotRaiseCoverage(t *testing.T) {
	pool := mitrePool(t)
	ctx := context.Background()

	seedRule(t, pool, "mitre-unmapped-"+uuid.NewString()[:8], "T9999")

	m, err := NewTracker(pool).Calculate(ctx, "24h")
	if err != nil {
		t.Fatalf("Calculate: %v", err)
	}
	if m.MITRECoverage[unknownTactic] == 0 {
		t.Fatalf("未対応テクニックが %q に入っていません: %v。"+
			"このテストが検証したい状況を作れていません",
			unknownTactic, m.MITRECoverage)
	}

	// A before/after delta cannot see this: the shared table already holds
	// unmapped techniques, so "unknown" is a bucket that exists either way and
	// adding one more rule to it moves no count. What has to be asserted is the
	// ceiling — the coverage figure cannot exceed what the real tactics support.
	//
	// There are 14 top-level ATT&CK tactics and the denominator is at least 14,
	// so counting "unknown" as a covered tactic shows up as a figure above this
	// bound. It is a bound rather than the formula, so it does not pass by
	// restating the code it is checking.
	realTactics := 0
	for tactic, n := range m.MITRECoverage {
		if tactic != unknownTactic && n > 0 {
			realTactics++
		}
	}
	const attackTactics = 14.0
	if bound := float64(realTactics) / attackTactics; m.DetectionCoverage > bound+1e-9 {
		t.Errorf("戦術カバレッジ = %.4f、上限 %.4f (実タクティク %d/%d)。"+
			"%q は戦術ではなく「対応表に無いテクニック」の置き場で、"+
			"分子に入れるとカバレッジが水増しされます: %v",
			m.DetectionCoverage, bound, realTactics, int(attackTactics),
			unknownTactic, m.MITRECoverage)
	}
}

// MTTD must stay nil, not 0. Nothing in this schema links an alert to the event
// that triggered it, so the mean time to detect cannot be computed at all —
// and a 0 on a SOC dashboard reads as instantaneous detection.
//
// The corresponding risk is that someone "fixes" the old query by renaming its
// three non-existent columns, producing a statement that runs and returns NULL
// for ever. That turns a loud failure into a silent zero, so the join is pinned
// out of the source here as well.
func TestMeanTimeToDetectIsAbsentRatherThanZero(t *testing.T) {
	pool := mitrePool(t)

	m, err := NewTracker(pool).Calculate(context.Background(), "24h")
	if err != nil {
		t.Fatalf("Calculate: %v", err)
	}
	if m.MTTD != nil {
		t.Errorf("MTTD = %v。アラートと発火イベントを結ぶものが無いので"+
			"算出できないはずです", *m.MTTD)
	}

	b, err := os.ReadFile("tracker.go")
	if err != nil {
		t.Fatalf("read tracker.go: %v", err)
	}
	src := stripLineComments(string(b))
	for _, join := range []string{"JOIN events", "join events"} {
		if strings.Contains(src, join) {
			t.Errorf("tracker.go が events を結合しています。" +
				"alerts.event_ids は SaveAlert の INSERT に含まれず、" +
				"events.alert_id には書き手がおらず、ingestion の " +
				"INSERT INTO events は id を返しません — " +
				"列名を直しても恒久的に NULL を返すクエリになるだけです")
			break
		}
	}
}

// stripLineComments removes `//` and `--` line comments, so the note explaining
// why the join was removed is not itself reported as the join.
func stripLineComments(src string) string {
	lines := strings.Split(src, "\n")
	for i, l := range lines {
		if j := strings.Index(l, "//"); j >= 0 {
			l = l[:j]
		}
		if j := strings.Index(l, "--"); j >= 0 {
			l = l[:j]
		}
		lines[i] = l
	}
	return strings.Join(lines, "\n")
}
