//go:build windows

package windows

import "testing"

func TestImagePathFromCommandLine(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"quoted full path", `"C:\Users\Administrator\ren5.exe"`, `C:\Users\Administrator\ren5.exe`},
		{"quoted with args", `"C:\Windows\System32\reg.exe" add HKCU\x`, `C:\Windows\System32\reg.exe`},
		{"unquoted full path", `C:\Windows\notepad.exe`, `C:\Windows\notepad.exe`},
		{"unquoted with args", `C:\tmp\a.exe -flag value`, `C:\tmp\a.exe`},
		{"unc path", `\\server\share\tool.exe /q`, `\\server\share\tool.exe`},
		{"leading space", `   C:\a\b.exe x`, `C:\a\b.exe`},
		// A bare basename is NOT a resolvable path — must be rejected so we don't
		// feed the file-based enrichment a name it would resolve against the wrong CWD.
		{"bare basename", `proc.exe -x`, ""},
		{"bare basename quoted", `"proc.exe"`, ""},
		{"empty", ``, ""},
		{"unbalanced quote", `"C:\a\b.exe`, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := imagePathFromCommandLine(c.in); got != c.want {
				t.Errorf("imagePathFromCommandLine(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}
