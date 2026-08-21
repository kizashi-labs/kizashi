package rulepack

import (
	"testing"

	detectionrules "github.com/edr-platform/server/internal/detection/rules"
)

// The pack validator and the detection engine must agree on how a platform may
// be spelled.
//
// They drifted once already. rules.platform has no CHECK constraint, the seeded
// content uses "macos" 159 times and "darwin" twice, and the engine's
// canonPlatform folds both onto the same value — so both match the same hosts.
// The validator, written from the column's DEFAULT rather than from the data,
// accepted only "darwin" and refused 159 working rules on the first export.
//
// A validator stricter than the engine does not make the system safer. It makes
// valid content unshippable, and the failure arrives at export time with no
// hint that the rules themselves are fine.
func TestPlatformVocabularyMatchesEngine(t *testing.T) {
	for spelling := range validPlatforms {
		if got := detectionrules.CanonPlatform(spelling); got == "" {
			t.Errorf("the pack accepts platform %q but the engine does not recognise it; "+
				"content using it would load and never match", spelling)
		}
	}

	// The other direction: anything the engine understands should be shippable.
	for _, spelling := range []string{"windows", "win", "linux", "macos", "darwin", "osx", "macosx", "mac"} {
		if detectionrules.CanonPlatform(spelling) == "" {
			continue // engine does not know it either; nothing to require
		}
		if !validPlatforms[spelling] {
			t.Errorf("the engine evaluates platform %q but the pack rejects it; "+
				"working content cannot be shipped", spelling)
		}
	}
}
