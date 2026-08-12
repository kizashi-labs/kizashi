package detection

import "testing"

func TestSuspiciousServiceImage(t *testing.T) {
	suspicious := []string{
		`C:\Windows\Temp\beacon.exe`,
		`C:\Users\Public\svc.exe`,
		`C:\Windows\System32\cmd.exe /c evil.bat`,
		`powershell.exe -enc SQBFAFgA`,
		`C:\ProgramData\update.ps1`,
		`rundll32.exe C:\a\b.dll,Start`,
		``, // empty ImagePath
		`C:\Users\v\AppData\Local\Temp\x.exe`,
	}
	for _, p := range suspicious {
		if suspiciousServiceImage(p) == "" {
			t.Errorf("expected %q to be flagged suspicious", p)
		}
	}

	benign := []string{
		`C:\Program Files\Contoso\ContosoSvc.exe`,
		`C:\Program Files (x86)\Vendor\agent.exe`,
		`C:\Windows\System32\svchost.exe -k netsvcs`,
	}
	for _, p := range benign {
		if r := suspiciousServiceImage(p); r != "" {
			t.Errorf("expected %q to be benign, flagged: %s", p, r)
		}
	}
}
