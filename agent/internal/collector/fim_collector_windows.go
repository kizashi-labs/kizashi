//go:build windows

package collector

// defaultFIMRules returns the default set of FIM rules for Windows.
// Watches the hosts file and key System32 files that are frequent targets
// for DLL hijacking, binary replacement, and persistence.
func defaultFIMRules() []FIMRule {
	return []FIMRule{
		// Hosts file — often modified by malware to redirect DNS.
		{
			Path:      `C:\Windows\System32\drivers\etc\hosts`,
			Recursive: false,
		},
		// System32 root (non-recursive — too many files for deep recursion).
		{
			Path:      `C:\Windows\System32`,
			Recursive: false,
			Exclude: []string{
				// Exclude volatile/log directories that change frequently.
				`C:\Windows\System32\catroot2`,
				`C:\Windows\System32\LogFiles`,
				`C:\Windows\System32\spool`,
				`C:\Windows\System32\winevt`,
			},
		},
		// SysWOW64 — 32-bit subsystem binaries.
		{
			Path:      `C:\Windows\SysWOW64`,
			Recursive: false,
			Exclude:   []string{},
		},
	}
}
