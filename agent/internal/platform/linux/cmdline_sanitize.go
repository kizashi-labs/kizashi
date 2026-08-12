//go:build linux

package linux

// hasCorruptBytes reports whether s contains non-printable control bytes that
// never appear in a legitimate process command line.
//
// The eBPF exec collector falls back to reading /proc/<pid>/cmdline when the
// in-kernel argv capture is empty. For kernel/runtime bootstrap processes —
// notably runc:[0:PARENT] and runc:[1:CHILD], whose argv region holds the
// serialized nsexec/netlink bootstrap state rather than a real command line —
// that read returns raw binary. Emitting it as a command line is harmful: it is
// pure noise, and its Cyrillic/Greek-looking bytes false-matched content rules
// (the SigmaHQ "Potential Homoglyph Attack" rule fired on it). Rejecting such
// values keeps command_line either correct or empty, never garbage.
//
// NUL (0x00) is intentionally NOT flagged: callers substitute it with a space
// (argv separator) before calling this. The common whitespace controls
// (TAB/LF/VT/FF/CR, 0x09–0x0d) are allowed; bytes >= 0x80 are allowed so UTF-8
// arguments survive.
func hasCorruptBytes(s string) bool {
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b < 0x09 || (b > 0x0d && b < 0x20) || b == 0x7f {
			return true
		}
	}
	return false
}
