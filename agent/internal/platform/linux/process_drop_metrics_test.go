//go:build linux && ebpf

package linux

import "testing"

// grewSince must fire only when a counter actually increases, so a healthy agent
// (steady counters) stays silent while any fresh telemetry loss is reported.
func TestDropSnapshot_GrewSince(t *testing.T) {
	cases := []struct {
		name       string
		prev, cur  dropSnapshot
		wantReport bool
	}{
		{"no change zero", dropSnapshot{0, 0}, dropSnapshot{0, 0}, false},
		{"no change nonzero", dropSnapshot{5, 3}, dropSnapshot{5, 3}, false},
		{"discarded grew", dropSnapshot{5, 3}, dropSnapshot{6, 3}, true},
		{"parseErr grew", dropSnapshot{5, 3}, dropSnapshot{5, 4}, true},
		{"both grew", dropSnapshot{0, 0}, dropSnapshot{2, 1}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.cur.grewSince(c.prev); got != c.wantReport {
				t.Errorf("grewSince(prev=%v, cur=%v) = %v, want %v", c.prev, c.cur, got, c.wantReport)
			}
		})
	}
}

// The atomic counters must be addressable and start at zero.
func TestDropCounters_Increment(t *testing.T) {
	before := procRecordsDiscarded.Load()
	procRecordsDiscarded.Add(1)
	if procRecordsDiscarded.Load() != before+1 {
		t.Fatalf("procRecordsDiscarded did not increment")
	}
	beforeP := procRecordsParseErr.Load()
	procRecordsParseErr.Add(2)
	if procRecordsParseErr.Load() != beforeP+2 {
		t.Fatalf("procRecordsParseErr did not increment")
	}
}
