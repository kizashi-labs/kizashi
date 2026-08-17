package buildvariant

import "testing"

// TestSuffixMatchesName pins the relationship between Name and Suffix, because
// the two are used in different places that must agree: Name goes on the
// update-check query, Suffix reconstructs the published filename. If they ever
// disagree the agent asks for one build and verifies the checksum of another.
//
// The test is tag-agnostic on purpose — it runs under every build variant and
// asserts the invariant rather than a specific value, so adding a variant does
// not require editing it.
func TestSuffixMatchesName(t *testing.T) {
	if Name == "" {
		if Suffix() != "" {
			t.Errorf("Suffix() = %q, want %q for the default build", Suffix(), "")
		}
		return
	}
	if want := "-" + Name; Suffix() != want {
		t.Errorf("Suffix() = %q, want %q", Suffix(), want)
	}
}

// TestNameIsAKnownVariant guards against a typo in a new variant_*.go file.
// The value must be one the server's allowedVariants accepts, or the agent
// self-updates into a permanent 400 loop.
func TestNameIsAKnownVariant(t *testing.T) {
	// Keep in sync with allowedVariants in
	// server/internal/api/handlers/download_handler.go.
	known := map[string]bool{"": true, "ebpf": true, "esf": true}
	if !known[Name] {
		t.Errorf("build variant %q is not in the server's accepted set; "+
			"add it to allowedVariants in download_handler.go too", Name)
	}
}
