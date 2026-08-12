//go:build windows

package windows

import "testing"

// TestIsSensitiveRegPathCoversNewASEPs locks in the registry ASEP fragments —
// including the COM (InprocServer32/LocalServer32), LSA package, and AppCertDlls
// keys added so the corresponding builtin Sigma rules have telemetry to fire on.
func TestIsSensitiveRegPathCoversNewASEPs(t *testing.T) {
	sensitive := []string{
		// COM hijacking (CLSID server paths).
		`\REGISTRY\USER\S-1-5-21-1\SOFTWARE\Classes\CLSID\{0006F03A-0000-0000-C000-000000000046}\InprocServer32`,
		`\REGISTRY\MACHINE\SOFTWARE\Classes\CLSID\{guid}\LocalServer32`,
		// LSA packages (password filter / SSP / auth package).
		`\REGISTRY\MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\Notification Packages`,
		`\REGISTRY\MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`,
		`\REGISTRY\MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\Security Packages`,
		// AppCert DLLs.
		`\REGISTRY\MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls`,
		// Pre-existing ASEPs (regression guard).
		`\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		`\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`,
	}
	for _, p := range sensitive {
		if !isSensitiveRegPath(p) {
			t.Errorf("expected sensitive, got false: %s", p)
		}
	}

	// Noise that must stay filtered out (avoid drowning the pipeline).
	benign := []string{
		`\REGISTRY\USER\S-1-5-21-1\SOFTWARE\Microsoft\Office\16.0\Word\Options`,
		`\REGISTRY\MACHINE\SOFTWARE\Classes\.txt`,
		``,
	}
	for _, p := range benign {
		if isSensitiveRegPath(p) {
			t.Errorf("expected benign, got sensitive: %s", p)
		}
	}
}
