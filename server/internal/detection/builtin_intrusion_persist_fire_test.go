package detection

import "testing"

// TestInitialAccessCloudRansomFire covers ISO/IMG container smuggling (initial access),
// serverless function tampering (cloud persistence), and anti-recovery free-space wipe /
// USN journal deletion (ransomware), each with benign negatives.
func TestInitialAccessCloudRansomFire(t *testing.T) {
	ev := NewSigmaEvaluator()
	LoadBuiltinRules(ev)

	fires := func(title string, event map[string]interface{}) bool {
		addPipelineSigmaAliases(event)
		for _, m := range ev.EvaluateEvent(event) {
			if m.RuleTitle == title {
				return true
			}
		}
		return false
	}
	proc := func(image, cmd string) map[string]interface{} {
		return map[string]interface{}{"type": "process", "image_path": image, "command_line": cmd}
	}

	pos := []struct{ title, image, cmd string }{
		{"Disk Image Mounted for Container Smuggling (ISO/IMG/VHD)", `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `powershell Mount-DiskImage -ImagePath C:\Users\v\Downloads\invoice.iso`},
		{"Cloud Serverless Function Tampering via CLI", `/usr/local/bin/aws`, `aws lambda update-function-code --function-name prod-api --zip-file fileb://evil.zip`},
		{"Anti-Recovery Free-Space Wipe or USN Journal Deletion", `C:\Windows\System32\cipher.exe`, `cipher /w:C:\`},
		{"Anti-Recovery Free-Space Wipe or USN Journal Deletion", `C:\Windows\System32\fsutil.exe`, `fsutil usn deletejournal /d /n C:`},
	}
	for _, tc := range pos {
		if !fires(tc.title, proc(tc.image, tc.cmd)) {
			t.Errorf("rule %q did not fire on %q", tc.title, tc.cmd)
		}
	}

	neg := []struct{ title, image, cmd string }{
		// Copying an .iso (no mount verb) → no fire.
		{"Disk Image Mounted for Container Smuggling (ISO/IMG/VHD)", `C:\Windows\System32\xcopy.exe`, `xcopy invoice.iso D:\backup\`},
		// Read-only Lambda listing → no fire.
		{"Cloud Serverless Function Tampering via CLI", `/usr/local/bin/aws`, `aws lambda list-functions`},
		// cipher encrypting (not /w free-space wipe) → no fire.
		{"Anti-Recovery Free-Space Wipe or USN Journal Deletion", `C:\Windows\System32\cipher.exe`, `cipher /e C:\secret`},
		// fsutil info query → no fire.
		{"Anti-Recovery Free-Space Wipe or USN Journal Deletion", `C:\Windows\System32\fsutil.exe`, `fsutil fsinfo drives`},
	}
	for _, tc := range neg {
		if fires(tc.title, proc(tc.image, tc.cmd)) {
			t.Errorf("rule %q should NOT fire on %q", tc.title, tc.cmd)
		}
	}
}
