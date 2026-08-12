//go:build darwin

package collector

import "testing"

func TestParsePSTime(t *testing.T) {
	cases := []struct {
		in   string
		want uint64 // centiseconds
	}{
		{"0:00.00", 0},
		{"0:00.50", 50},
		{"0:01.00", 100},
		{"0:01.23", 123},
		{"1:00.00", 6000},        // 1 minute
		{"1:23.45", 8345},        // 1m23.45s
		{"1:00:00", 360000},      // 1 hour
		{"1:02:03", 372300},      // 1h02m03s
		{"2-01:00:00", 17640000}, // 2 days + 1 hour
		{"12:34", 75400},         // mm:ss (no fraction)
	}
	for _, c := range cases {
		if got := parsePSTime(c.in); got != c.want {
			t.Errorf("parsePSTime(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}
