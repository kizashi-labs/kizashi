//go:build linux

package linux

import "testing"

// TestHasCorruptBytes guards the command_line corruption filter that stops the
// eBPF /proc fallback from emitting binary runc-bootstrap argv as a command line
// (which produced noise and false-matched the SigmaHQ homoglyph rule).
func TestHasCorruptBytes(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		// Legitimate command lines must pass (want=false).
		{"plain", "whoami", false},
		{"with args", "curl -s -o /tmp/x https://example.com", false},
		{"runc real cmdline (printable)", "runc --systemd-cgroup exec --process /tmp/runc-process1486944787 --detach", false},
		{"utf8 args", "grep 日本語 file.txt", false},
		{"tab and newline allowed", "sh -c 'echo a\tb\nc'", false},
		{"empty", "", false},
		// Corrupt / binary values must be rejected (want=true).
		{"runc nsexec bootstrap garbage", "ab7f142.pid 797e8f3a\x01\x038\x03\x07 uZ*\x19 runc /usr/bin", true},
		{"low control bytes", "cmd\x01\x02\x03", true},
		{"del byte", "cmd\x7f", true},
		{"high control 0x1e", "a\x1eb", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := hasCorruptBytes(c.in); got != c.want {
				t.Errorf("hasCorruptBytes(%q) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}
