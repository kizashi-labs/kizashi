//go:build windows && prevention

package windows

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// containsFold reports whether ss holds want (case-insensitively). Named for the
// fold-compare rather than plain `contains`: auth_parse_test.go in this package
// already declares a substring `contains`, and under `-tags prevention` the two
// files compile together. That collision meant this test file had never been
// compiled at all — no CI job type-checked the windows+prevention build.
func containsFold(ss []string, want string) bool {
	for _, s := range ss {
		if strings.EqualFold(s, want) {
			return true
		}
	}
	return false
}

// TestPathAliasesExistingFile verifies that an existing drive-rooted file expands
// to (at least) itself and its \Device\HarddiskVolumeN form, and — when the
// volume keeps 8.3 names — to its short/long counterparts. This is the W2 NT→DOS
// normalization that bridges the kernel's NT image path to the rule's DOS path.
func TestPathAliasesExistingFile(t *testing.T) {
	dir := t.TempDir()
	// A long base name (>8 chars before the dot) so an 8.3 short form differs.
	long := filepath.Join(dir, "blockme_longname.exe")
	if err := os.WriteFile(long, []byte("MZ"), 0o644); err != nil {
		t.Fatalf("write temp: %v", err)
	}

	aliases := PathAliases(long)
	t.Logf("aliases(%q) = %v", long, aliases)

	if !containsFold(aliases, long) {
		t.Errorf("aliases must contain the input path %q; got %v", long, aliases)
	}

	// Device form: \Device\HarddiskVolumeN\... — always available for a drive path.
	hasDevice := false
	for _, a := range aliases {
		if strings.HasPrefix(strings.ToLower(a), `\device\`) {
			hasDevice = true
		}
	}
	if !hasDevice {
		t.Errorf("expected a \\Device\\ form among aliases; got %v", aliases)
	}

	// Short form: if the volume preserves 8.3 names, GetShortPathName differs and
	// must be present (this is exactly the ADMINI~1 case from W0 testing).
	if sp := shortPath(long); sp != "" && !strings.EqualFold(sp, long) {
		if !containsFold(aliases, sp) {
			t.Errorf("short-name form %q missing from aliases %v", sp, aliases)
		}
		// And expanding the short form must recover the long form.
		back := PathAliases(sp)
		if !containsFold(back, longPath(sp)) {
			t.Errorf("expanding short form %q should include its long form; got %v", sp, back)
		}
	} else {
		t.Logf("8.3 short names not available on this volume; skipped short/long cross-check")
	}
}

// TestPathAliasesMissingFile: a non-existent path still yields itself + a device
// form (long/short resolution fails gracefully).
func TestPathAliasesMissingFile(t *testing.T) {
	p := `C:\definitely\does\not\exist\evil.exe`
	aliases := PathAliases(p)
	if !containsFold(aliases, p) {
		t.Errorf("missing-file aliases must still contain the input; got %v", aliases)
	}
}
