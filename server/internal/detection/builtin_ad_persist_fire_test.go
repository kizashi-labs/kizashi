package detection

import "testing"

// TestADAndLogonScriptPersistenceFire covers domain-wide persistence/tampering rules:
// GPO tampering (T1484.001), Windows logon-script persistence via registry (T1037.001)
// and via NETLOGON/SYSVOL deployment (T1037.003), and DC authentication tampering via
// DCShadow/AdminSDHolder abuse (T1556.001), each with benign negatives.
func TestADAndLogonScriptPersistenceFire(t *testing.T) {
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
	reg := func(targetObject string) map[string]interface{} {
		return map[string]interface{}{"type": "registry", "key_path": targetObject, "value_name": ""}
	}

	pos := []struct {
		title string
		event map[string]interface{}
	}{
		{"Domain Policy Modification via GPO Tampering",
			proc(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `New-GPO -Name "evil-policy" -Comment "backdoor"`)},
		{"Domain Policy Modification via GPO Tampering",
			proc(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `Set-GPRegistryValue -Name "Default Domain Policy" -Key "HKLM\Software\Policies\Microsoft\Windows Defender" -ValueName DisableAntiSpyware -Type DWORD -Value 1`)},
		{"Domain Policy Modification via GPO Tampering",
			proc(`C:\Users\Public\SharpGPOAbuse.exe`, `SharpGPOAbuse.exe --AddComputerTask --TaskName evil --Author DOMAIN\Administrator --Command cmd.exe --GPOName "Default Domain Policy"`)},
		{"Windows Logon Script Persistence via Registry",
			reg(`HKCU\Environment\UserInitMprLogonScript`)},
		{"Network Logon Script Deployment via NETLOGON or SYSVOL Share",
			proc(`C:\Windows\System32\robocopy.exe`, `robocopy C:\staging \\corp.local\NETLOGON\ evil.bat`)},
		{"Network Logon Script Deployment via NETLOGON or SYSVOL Share",
			proc(`C:\Windows\System32\xcopy.exe`, `xcopy evil.vbs \\corp.local\SYSVOL\corp.local\scripts\`)},
		{"Domain Controller Authentication Tampering (DCShadow/AdminSDHolder Abuse)",
			proc(`C:\Users\Public\mimikatz.exe`, `mimikatz.exe "lsadump::dcshadow /object:evil" "/pushmode"`)},
		{"Domain Controller Authentication Tampering (DCShadow/AdminSDHolder Abuse)",
			proc(`C:\Windows\System32\dsacls.exe`, `dsacls.exe "CN=AdminSDHolder,CN=System,DC=corp,DC=local" /G evil:GA`)},
	}
	for _, tc := range pos {
		if !fires(tc.title, tc.event) {
			t.Errorf("rule %q did not fire on %+v", tc.title, tc.event)
		}
	}

	neg := []struct {
		title string
		event map[string]interface{}
	}{
		// Read-only GPO report/backup → no fire.
		{"Domain Policy Modification via GPO Tampering",
			proc(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `Get-GPOReport -All -ReportType HTML -Path report.html`)},
		// A different registry value under Environment, not the logon-script key → no fire.
		{"Windows Logon Script Persistence via Registry",
			reg(`HKCU\Environment\TEMP`)},
		// Local file copy, no NETLOGON/SYSVOL target → no fire.
		{"Network Logon Script Deployment via NETLOGON or SYSVOL Share",
			proc(`C:\Windows\System32\robocopy.exe`, `robocopy C:\src C:\backup /mir`)},
		// mimikatz privilege::debug (no dcshadow) → no fire.
		{"Domain Controller Authentication Tampering (DCShadow/AdminSDHolder Abuse)",
			proc(`C:\Users\Public\mimikatz.exe`, `mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords"`)},
		// dsacls query against an unrelated object → no fire.
		{"Domain Controller Authentication Tampering (DCShadow/AdminSDHolder Abuse)",
			proc(`C:\Windows\System32\dsacls.exe`, `dsacls.exe "CN=Users,DC=corp,DC=local"`)},
	}
	for _, tc := range neg {
		if fires(tc.title, tc.event) {
			t.Errorf("rule %q should NOT fire on %+v", tc.title, tc.event)
		}
	}
}
