package scheduler

import (
	"strings"
	"testing"
)

func TestExpirySeverity_Expired(t *testing.T) {
	// daysLeft < 1 covers both 0 (expires today) and negative (already past).
	for _, d := range []int{0, -1, -5, -90} {
		sev, title, notify := expirySeverity(d, "APNs Push Certificate")
		if !notify {
			t.Fatalf("daysLeft=%d must trigger notify", d)
		}
		if sev != 9 {
			t.Fatalf("daysLeft=%d want severity 9, got %d", d, sev)
		}
		if !strings.Contains(title, "期限切れ") || !strings.Contains(title, "APNs Push Certificate") {
			t.Fatalf("title missing keyword or name: %q", title)
		}
	}
}

func TestExpirySeverity_Warning(t *testing.T) {
	// 1..6 days → severity 7, "まもなく" language.
	for _, d := range []int{1, 3, 6} {
		sev, title, notify := expirySeverity(d, "AE SA Key")
		if !notify {
			t.Fatalf("daysLeft=%d must trigger notify", d)
		}
		if sev != 7 {
			t.Fatalf("daysLeft=%d want severity 7, got %d", d, sev)
		}
		if !strings.Contains(title, "まもなく") {
			t.Fatalf("7-day bucket should use まもなく language, got: %q", title)
		}
	}
}

func TestExpirySeverity_Informational(t *testing.T) {
	// 7..29 days → severity 3, advisory language.
	for _, d := range []int{7, 15, 29} {
		sev, _, notify := expirySeverity(d, "ABM Server Token")
		if !notify {
			t.Fatalf("daysLeft=%d must trigger notify at sev3", d)
		}
		if sev != 3 {
			t.Fatalf("daysLeft=%d want severity 3, got %d", d, sev)
		}
	}
}

func TestExpirySeverity_HealthySkip(t *testing.T) {
	// >= 30 days → no alert.
	for _, d := range []int{30, 60, 365} {
		sev, title, notify := expirySeverity(d, "APNs")
		if notify || sev != 0 || title != "" {
			t.Fatalf("daysLeft=%d should be silent, got sev=%d notify=%v title=%q", d, sev, notify, title)
		}
	}
}

// Boundary verification: the exact switch cutoffs matter because a
// one-off can silently downgrade a sev-7 alert to sev-3.
func TestExpirySeverity_Boundaries(t *testing.T) {
	cases := []struct {
		daysLeft int
		wantSev  int
	}{
		{-1, 9}, // expired
		{0, 9},  // expiring today
		{1, 7},  // first warning day
		{6, 7},  // last warning day
		{7, 3},  // first informational day
		{29, 3}, // last informational day
		{30, 0}, // first healthy day (no alert)
	}
	for _, c := range cases {
		sev, _, notify := expirySeverity(c.daysLeft, "X")
		if c.wantSev == 0 {
			if notify {
				t.Fatalf("daysLeft=%d want silent, got notify=true sev=%d", c.daysLeft, sev)
			}
			continue
		}
		if sev != c.wantSev {
			t.Fatalf("daysLeft=%d want sev=%d, got sev=%d", c.daysLeft, c.wantSev, sev)
		}
	}
}
