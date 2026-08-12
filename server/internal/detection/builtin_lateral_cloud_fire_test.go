package detection

import "testing"

// TestLateralAndCloudControlPlaneFire covers the Windows remote lateral-movement rules
// (remote sc / schtasks / wmic) and the cloud control-plane abuse rules (logging disabled,
// security service disabled, IAM privilege escalation), each with benign negatives.
func TestLateralAndCloudControlPlaneFire(t *testing.T) {
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
		{"Remote Service Creation via sc.exe", `C:\Windows\System32\sc.exe`, `sc \\victim create evilsvc binpath= C:\Users\Public\p.exe`},
		{"Remote Scheduled Task Creation via schtasks", `C:\Windows\System32\schtasks.exe`, `schtasks /create /s \\dc01 /tn upd /tr calc.exe /sc onstart`},
		{"Remote WMI Process Creation via wmic", `C:\Windows\System32\wbem\wmic.exe`, `wmic /node:10.0.0.5 process call create "cmd /c calc"`},
		{"Cloud Logging Disabled via CLI", `/usr/local/bin/aws`, `aws cloudtrail stop-logging --name org-trail`},
		{"Cloud Security Service Disabled via CLI", `/usr/local/bin/aws`, `aws guardduty delete-detector --detector-id 1a2b3c`},
		{"Cloud IAM Privilege Escalation via CLI", `/usr/local/bin/aws`, `aws iam attach-user-policy --user-name bob --policy-arn arn:aws:iam::aws:policy/AdministratorAccess`},
		{"Cloud IAM Privilege Escalation via CLI", `/usr/bin/gcloud`, `gcloud projects add-iam-policy-binding proj --member user:x@y --role roles/owner`},
		{"Cloud IAM Privilege Escalation via CLI", `/usr/bin/az`, `az role assignment create --assignee x --role Owner --scope /subscriptions/abc`},
	}
	for _, tc := range pos {
		if !fires(tc.title, proc(tc.image, tc.cmd)) {
			t.Errorf("rule %q did not fire on %q", tc.title, tc.cmd)
		}
	}

	neg := []struct{ title, image, cmd string }{
		// Local service creation (no UNC host) → no fire.
		{"Remote Service Creation via sc.exe", `C:\Windows\System32\sc.exe`, `sc create localsvc binpath= C:\Program Files\App\svc.exe`},
		// Local scheduled task (no /s) → no fire.
		{"Remote Scheduled Task Creation via schtasks", `C:\Windows\System32\schtasks.exe`, `schtasks /create /tn backup /tr backup.exe /sc daily`},
		// Local wmic query → no fire.
		{"Remote WMI Process Creation via wmic", `C:\Windows\System32\wbem\wmic.exe`, `wmic process list brief`},
		// Read-only CloudTrail → no fire.
		{"Cloud Logging Disabled via CLI", `/usr/local/bin/aws`, `aws cloudtrail describe-trails`},
		// Attaching a NON-admin policy → no fire (no admin indicator).
		{"Cloud IAM Privilege Escalation via CLI", `/usr/local/bin/aws`, `aws iam attach-user-policy --user-name bob --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess`},
	}
	for _, tc := range neg {
		if fires(tc.title, proc(tc.image, tc.cmd)) {
			t.Errorf("rule %q should NOT fire on %q", tc.title, tc.cmd)
		}
	}
}
