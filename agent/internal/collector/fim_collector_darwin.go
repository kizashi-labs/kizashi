//go:build darwin

package collector

// defaultFIMRules returns the default set of FIM rules for macOS.
// Focuses on system-level files modified by macOS-specific malware and
// privilege escalation techniques.
func defaultFIMRules() []FIMRule {
	return []FIMRule{
		// Standard Unix sensitive files present on macOS.
		{Path: "/etc/hosts", Recursive: false},
		{Path: "/etc/passwd", Recursive: false},
		{Path: "/etc/sudoers", Recursive: false},
		{Path: "/etc/ssh/sshd_config", Recursive: false},
		// macOS-specific persistence locations.
		{
			Path:      "/Library/LaunchDaemons",
			Recursive: false,
			Exclude:   []string{},
		},
		{
			Path:      "/Library/LaunchAgents",
			Recursive: false,
			Exclude:   []string{},
		},
		// System binaries (non-recursive).
		{
			Path:      "/usr/bin",
			Recursive: false,
			Exclude:   []string{},
		},
		{
			Path:      "/usr/sbin",
			Recursive: false,
			Exclude:   []string{},
		},
		{
			Path:      "/bin",
			Recursive: false,
			Exclude:   []string{},
		},
		{
			Path:      "/sbin",
			Recursive: false,
			Exclude:   []string{},
		},
	}
}
