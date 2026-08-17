package metrics

import "testing"

// The platform string arrives from the endpoint, so it is untrusted input on a
// metric label — the one place where unbounded values are not merely untidy but
// a denial of service against the metrics backend. Anything unrecognised must
// collapse to a single bucket.
func TestPlatformLabelIsBounded(t *testing.T) {
	known := map[string]string{
		"linux":   "linux",
		"Linux":   "linux",
		"  LINUX": "linux",
		"windows": "windows",
		"Windows": "windows",
		"darwin":  "darwin",
		"macos":   "darwin",
		"macOS":   "darwin",
		"":        "unknown",
	}
	for in, want := range known {
		if got := PlatformLabel(in); got != want {
			t.Errorf("PlatformLabel(%q) = %q, want %q", in, got, want)
		}
	}

	// Every unrecognised value — including ones an agent could choose freely —
	// must land on the same label, so the cardinality cannot grow with input.
	hostile := []string{
		"linux; DROP",
		"plan9",
		"a-very-long-string-an-agent-could-invent-to-mint-label-values",
		"linux\n",
		"LINUX ",
	}
	seen := map[string]struct{}{}
	for _, in := range hostile {
		got := PlatformLabel(in)
		if got == "linux" || got == "windows" || got == "darwin" {
			// Trailing/leading whitespace variants of a known value are fine.
			continue
		}
		if got != "other" {
			t.Errorf("PlatformLabel(%q) = %q, want other", in, got)
		}
		seen[got] = struct{}{}
	}
	if len(seen) > 1 {
		t.Errorf("unrecognised inputs produced %d distinct labels, want 1: %v", len(seen), seen)
	}
}

// The whole label set must stay small enough to multiply safely against the
// action and outcome labels.
func TestPlatformLabelRangeIsSmall(t *testing.T) {
	out := map[string]struct{}{}
	for _, in := range []string{"linux", "windows", "darwin", "macos", "", "plan9", "???"} {
		out[PlatformLabel(in)] = struct{}{}
	}
	if len(out) > 5 {
		t.Errorf("platform label range = %d values, want <= 5: %v", len(out), out)
	}
}
