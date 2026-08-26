package detection

import "testing"

// TestLateralMovementDeepeningFire covers the deepened Windows lateral-movement rules:
// the actual attacker payload spawned by PSEXESVC.exe / wsmprovhost.exe (not just the
// tool's own presence), PsExec-alternative tools (PAExec/RemCom), PowerShell
// Invoke-Command remoting, and WinRM enablement, each with benign negatives.
func TestLateralMovementDeepeningFire(t *testing.T) {
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
	proc := func(image, parentImage, cmd string) map[string]interface{} {
		return map[string]interface{}{
			"type":              "process",
			"image_path":        image,
			"parent_image_path": parentImage,
			"command_line":      cmd,
		}
	}

	pos := []struct{ title, image, parentImage, cmd string }{
		{"Process Spawned by PsExec Service (Attacker Payload)",
			`C:\Windows\System32\cmd.exe`, `C:\Windows\PSEXESVC.exe`, `cmd /c whoami`},
		{"PsExec-Alternative Remote Execution Tool (PAExec/RemCom)",
			`C:\Users\Public\paexec.exe`, `C:\Windows\explorer.exe`, `paexec \\10.0.0.5 -s cmd.exe`},
		{"PsExec-Alternative Remote Execution Tool (PAExec/RemCom)",
			`C:\Users\Public\remcom.exe`, `C:\Windows\explorer.exe`, `remcom \\10.0.0.5 cmd.exe`},
		{"Process Spawned by WinRM Remote Shell Host (Attacker Payload)",
			`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `C:\Windows\System32\wsmprovhost.exe`, `powershell -enc ...`},
		{"PowerShell Remote Command Execution via Invoke-Command",
			`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `C:\Windows\explorer.exe`,
			`Invoke-Command -ComputerName dc01 -ScriptBlock { whoami }`},
		{"PowerShell Remote Command Execution via Invoke-Command",
			`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `C:\Windows\explorer.exe`,
			`Invoke-Command -Session $s -ScriptBlock { calc }`},
		{"WinRM Remote Management Enabled",
			`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `C:\Windows\explorer.exe`, `Enable-PSRemoting -Force`},
		{"WinRM Remote Management Enabled",
			`C:\Windows\System32\cmd.exe`, `C:\Windows\explorer.exe`, `winrm quickconfig -q`},
	}
	for _, tc := range pos {
		if !fires(tc.title, proc(tc.image, tc.parentImage, tc.cmd)) {
			t.Errorf("rule %q did not fire on image=%q parent=%q cmd=%q", tc.title, tc.image, tc.parentImage, tc.cmd)
		}
	}

	neg := []struct{ title, image, parentImage, cmd string }{
		// cmd.exe spawned by the normal service host, not PSEXESVC → no fire.
		{"Process Spawned by PsExec Service (Attacker Payload)",
			`C:\Windows\System32\cmd.exe`, `C:\Windows\System32\services.exe`, `cmd /c whoami`},
		// Plain cmd.exe, no PAExec/RemCom binary → no fire.
		{"PsExec-Alternative Remote Execution Tool (PAExec/RemCom)",
			`C:\Windows\System32\cmd.exe`, `C:\Windows\explorer.exe`, `cmd /c whoami`},
		// powershell.exe spawned by explorer (interactive), not wsmprovhost → no fire.
		{"Process Spawned by WinRM Remote Shell Host (Attacker Payload)",
			`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `C:\Windows\explorer.exe`, `powershell -Command Get-Process`},
		// Invoke-Command with no -ComputerName/-Session (local scriptblock) → no fire.
		{"PowerShell Remote Command Execution via Invoke-Command",
			`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `C:\Windows\explorer.exe`,
			`Invoke-Command -ScriptBlock { Get-Process }`},
		// Read-only WinRM query, not quickconfig/enable → no fire.
		{"WinRM Remote Management Enabled",
			`C:\Windows\System32\cmd.exe`, `C:\Windows\explorer.exe`, `winrm get winrm/config`},
	}
	for _, tc := range neg {
		if fires(tc.title, proc(tc.image, tc.parentImage, tc.cmd)) {
			t.Errorf("rule %q should NOT fire on image=%q parent=%q cmd=%q", tc.title, tc.image, tc.parentImage, tc.cmd)
		}
	}
}
