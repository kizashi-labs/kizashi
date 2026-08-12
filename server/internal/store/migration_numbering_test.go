package store

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Migration numbers must be unique.
//
// CLAUDE.md says to add new migrations "with the next unused number", and that
// convention has quietly stopped holding: 16 numeric prefixes are shared by two
// or three files, 329 by three. Nothing enforced it, so nothing noticed.
//
// This is not currently a correctness bug. migrate.go sorts by the FULL filename
// (`sort.Strings(files)`), so the apply order is deterministic. But it is
// deterministic in ALPHABETICAL order, which is not the order anyone intended:
// 324_agent_metrics.sql runs before 324_rls_force_tenant_isolation.sql because
// "a" < "r", not because that is the right sequence. Two migrations sharing a
// number are two migrations whose relative order was never chosen — it was
// decided by their titles. A future pair where one depends on the other will
// break, and it will break as "the second one failed" rather than as "these
// share a number".
//
// The existing 16 are grandfathered rather than renamed. schema_migrations
// stores the full filename as the version, so renaming a migration that has
// already been applied makes the runner see a NEW file and run it again — and
// many of these are not idempotent (a bare ALTER TABLE ... ADD CONSTRAINT fails
// on the second pass). Renaming them would break every existing deployment to
// tidy up a naming convention. Not worth it; stopping the growth is.
var grandfatheredDuplicateMigrationNumbers = map[string]bool{
	"029": true, "200": true, "315": true, "322": true, "323": true,
	"324": true, "325": true, "326": true, "327": true, "328": true,
	"329": true, "330": true, "331": true, "340": true, "357": true,
	"365": true,
}

var migrationPrefixRe = regexp.MustCompile(`^(\d+)_`)

func migrationFilesByNumber(t *testing.T) map[string][]string {
	t.Helper()
	dir := filepath.Join("..", "..", "migrations")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read migrations: %v", err)
	}
	out := map[string][]string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		m := migrationPrefixRe.FindStringSubmatch(e.Name())
		if m == nil {
			t.Errorf("%s does not start with a numeric prefix — migrate.go orders by filename, "+
				"so a file outside the NNN_ convention sorts unpredictably against the rest", e.Name())
			continue
		}
		out[m[1]] = append(out[m[1]], e.Name())
	}
	for k := range out {
		sort.Strings(out[k])
	}
	return out
}

func TestMigrationNumbersAreUnique(t *testing.T) {
	byNumber := migrationFilesByNumber(t)
	if len(byNumber) < 300 {
		t.Fatalf("only %d migration numbers found — the scan is broken and this test would "+
			"pass vacuously", len(byNumber))
	}

	nums := make([]string, 0, len(byNumber))
	for n := range byNumber {
		nums = append(nums, n)
	}
	sort.Strings(nums)

	for _, n := range nums {
		files := byNumber[n]
		if len(files) == 1 || grandfatheredDuplicateMigrationNumbers[n] {
			continue
		}
		t.Errorf("migration number %s is used by %d files: %s\n"+
			"  Pick the next unused number. Two migrations sharing a number have no chosen "+
			"relative order — migrate.go sorts by full filename, so their sequence is decided "+
			"by their titles, alphabetically. Do NOT fix this by renaming an already-applied "+
			"migration: schema_migrations records the filename, so a rename re-runs it.",
			n, len(files), strings.Join(files, ", "))
	}
}

// The grandfather list must stay honest. If someone renames or removes one of
// the historical duplicates, the entry becomes a licence for a NEW duplicate at
// that number — the check would go quiet exactly where it was already weakest.
func TestGrandfatheredMigrationDuplicatesStillExist(t *testing.T) {
	byNumber := migrationFilesByNumber(t)

	var stale []string
	for n := range grandfatheredDuplicateMigrationNumbers {
		if len(byNumber[n]) <= 1 {
			stale = append(stale, fmt.Sprintf(
				"%s is listed as a historical duplicate but now has %d file(s) — remove it from "+
					"grandfatheredDuplicateMigrationNumbers, or it silently permits a new collision there",
				n, len(byNumber[n])))
		}
	}
	sort.Strings(stale)
	for _, s := range stale {
		t.Error(s)
	}
}
