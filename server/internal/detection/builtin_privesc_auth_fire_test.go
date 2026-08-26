package detection

import "testing"

// TestPrivescAndAuthRulesFire covers the Linux privilege-escalation discovery/primitives
// (SUID/cap discovery, dangerous setcap, capsh) and the Windows auth-abuse rules (Kerberos
// golden/silver ticket forgery, DPAPI secret extraction), with benign negatives.
func TestPrivescAndAuthRulesFire(t *testing.T) {
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
		{"SUID/SGID or Capabilities Discovery (Linux)", "/usr/bin/find", "find / -perm -4000 -type f 2>/dev/null"},
		{"SUID/SGID or Capabilities Discovery (Linux)", "/usr/sbin/getcap", "getcap -r / 2>/dev/null"},
		{"Dangerous Capability Assignment via setcap (Linux)", "/usr/sbin/setcap", "setcap cap_setuid+ep /tmp/rootme"},
		{"Capsh Privilege Escalation (Linux)", "/usr/sbin/capsh", "capsh --gid=0 --uid=0 --"},
		{"Kerberos Golden or Silver Ticket Forgery", `C:\Users\Public\mk.exe`, `mk.exe "kerberos::golden /user:Administrator /domain:corp /krbtgt:deadbeef /id:500"`},
		{"DPAPI Master Key or Secret Extraction", `C:\Users\Public\mk.exe`, `mk.exe "dpapi::masterkey /in:C:\Users\v\AppData\...\masterkey /rpc"`},
	}
	for _, tc := range pos {
		if !fires(tc.title, proc(tc.image, tc.cmd)) {
			t.Errorf("rule %q did not fire on %q", tc.title, tc.cmd)
		}
	}

	neg := []struct{ title, image, cmd string }{
		// A normal find that is not a SUID/cap scan.
		{"SUID/SGID or Capabilities Discovery (Linux)", "/usr/bin/find", "find / -name '*.conf' -type f"},
		// setcap granting cap_net_raw to ping is benign (not in the dangerous set).
		{"Dangerous Capability Assignment via setcap (Linux)", "/usr/sbin/setcap", "setcap cap_net_raw+ep /bin/ping"},
		// capsh --print is introspection, not a root-shell escape.
		{"Capsh Privilege Escalation (Linux)", "/usr/sbin/capsh", "capsh --print"},
		// Benign Kerberos tooling.
		{"Kerberos Golden or Silver Ticket Forgery", `C:\Windows\System32\klist.exe`, "klist"},
	}
	for _, tc := range neg {
		if fires(tc.title, proc(tc.image, tc.cmd)) {
			t.Errorf("rule %q should NOT fire on %q", tc.title, tc.cmd)
		}
	}
}
