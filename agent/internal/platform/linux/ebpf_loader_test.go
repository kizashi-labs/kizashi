//go:build linux && ebpf

package linux

import "testing"

func TestArgvToCmdline(t *testing.T) {
	mk := func(s string) []byte {
		b := make([]byte, 512)
		copy(b, s)
		return b
	}
	tests := []struct {
		name string
		buf  []byte
		n    uint32
		want string
	}{
		{"empty (no capture)", mk(""), 0, ""},
		{"single arg", mk("whoami\x00"), 7, "whoami"},
		{"multi arg NUL-separated", mk("base64\x00-d\x00"), 10, "base64 -d"},
		{"reverse shell cmdline", mk("bash\x00-c\x00cat < /dev/tcp/127.0.0.1/9\x00"), 35, "bash -c cat < /dev/tcp/127.0.0.1/9"},
		{"trailing NULs trimmed", mk("id\x00\x00\x00"), 5, "id"},
		{"n clamped to buffer length", mk("ls"), 99999, "ls"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := argvToCmdline(tc.buf, tc.n); got != tc.want {
				t.Errorf("argvToCmdline(%q, %d) = %q, want %q", tc.buf[:min(int(tc.n), len(tc.buf))], tc.n, got, tc.want)
			}
		})
	}
}
