package detection

import (
	"strings"
	"testing"
)

// builtinPrimaryTech extracts a builtin rule's title and the FIRST attack.t* tag,
// mirroring parseMITRETechFromTags — which is what AlertPipeline.createAlertFromSigma
// stores as the alert's mitre_technique. So this is exactly the value an analyst
// (and the attack-scorer) sees for an alert from this rule.
func builtinPrimaryTech(ruleYAML string) (title, tech string) {
	for ln := range strings.SplitSeq(ruleYAML, "\n") {
		s := strings.TrimSpace(ln)
		if title == "" && strings.HasPrefix(s, "title:") {
			title = strings.TrimSpace(strings.TrimPrefix(s, "title:"))
		}
		if tech == "" {
			low := strings.ToLower(s)
			if strings.HasPrefix(low, "- attack.t") {
				tech = strings.ToUpper(strings.TrimSpace(strings.TrimPrefix(low, "- attack.")))
			}
		}
	}
	return title, tech
}

// TestBuiltinSigmaPrimaryTechnique guards the primary ATT&CK technique of builtin
// Sigma rules whose tag ORDER matters (multi-technique rules). The alert's
// mitre_technique is the first attack.t* tag (parseMITRETechFromTags); if a rule
// lists a broad sibling first (e.g. T1112 Modify Registry before T1547.001 Run Key
// persistence), the alert is mislabelled and per-technique attribution misses it.
//
// Regression context (2026-06-22): "Registry Run Key Persistence" shipped with
// tags [t1112, t1547.001] → alerts came out as T1112, so Windows persistence
// detection looked like a MISS. The fix reordered the specific technique first.
func TestBuiltinSigmaPrimaryTechnique(t *testing.T) {
	want := map[string]string{
		"Registry Run Key Persistence":                      "T1547.001",
		"Scheduled Task Creation via schtasks":              "T1053.005",
		"Encoded PowerShell Command Execution":              "T1059.001",
		"LSASS Memory Dump via Process Access":              "T1003.001",
		"Windows Service Creation via sc.exe":               "T1543.003",
		"MSBuild Proxy Execution":                           "T1127.001",
		"Image File Execution Options Debugger Persistence": "T1546.012",
		"AppInit DLLs Persistence":                          "T1546.001",
		"Logon Script Persistence (UserInitMprLogonScript)": "T1037.001",
		"Windows Defender Tampering via Registry":           "T1562.001",
		"Web Server Spawning Command Shell (Web Shell)":     "T1505.003",
		"Hidden File or Directory via attrib":               "T1564.001",
		"Broad File Permission Change via icacls/takeown":   "T1222.001",
		"Domain Account Creation via net.exe":               "T1136.002",
		// The local half of the discovery split (the domain half is pinned further
		// down): each rule must report its OWN sub-technique, or the pair collapses
		// back into one attribution.
		"Local Account Discovery":                                   "T1087.001",
		"Local Permission Groups Discovery":                         "T1069.001",
		"DCSync Credential Replication":                             "T1003.006",
		"Windows Credential Manager Access":                         "T1555.004",
		"RDP Enabled or Session Hijack":                             "T1021.001",
		"WinRM Lateral Movement (winrs / PowerShell Remoting)":      "T1021.006",
		"Internal Proxy via netsh portproxy":                        "T1090.001",
		"Regsvcs/Regasm Proxy Execution":                            "T1218.009",
		"Root Certificate Installation via certutil":                "T1553.004",
		"XSL Script Processing Proxy Execution":                     "T1220",
		"Clipboard Data Collection":                                 "T1115",
		"Screen Capture via CopyFromScreen / Screenshot Tool":       "T1113",
		"Keylogging via Windows Hook / Async Key State":             "T1056.001",
		"Email Collection via Mailbox Export":                       "T1114",
		"LSA Secrets Dump":                                          "T1003.004",
		"Cached Domain Credentials Dump":                            "T1003.005",
		"Private Key Harvesting":                                    "T1552.004",
		"LLMNR/NBT-NS Poisoning Tool (Responder/Inveigh)":           "T1557.001",
		"Group Policy Preferences Password Retrieval":               "T1552.006",
		"System Process Name From Non-Standard Path (Masquerading)": "T1036.003",
		"Hidden Window Execution":                                   "T1564.003",
		"NTFS Alternate Data Stream Manipulation":                   "T1564.004",
		"Timestomping (File Time Modification)":                     "T1070.006",
		"Windows Event Logging Disabled":                            "T1562.002",
		"SSH Lateral Movement with Inline Credentials":              "T1021.004",
		"DCOM Lateral Movement":                                     "T1021.003",
		"Pass-the-Ticket (Kerberos Ticket Injection)":               "T1550.003",
		"Access Token Manipulation":                                 "T1134",
		"Cryptocurrency Mining (Resource Hijacking)":                "T1496",
		"Disk Wipe / Destruction":                                   "T1561",
		"Account Access Removal":                                    "T1531",
		"Sudo Privilege Escalation via Shell Escape (GTFOBins)":     "T1548.003",
		"Clear Linux Command History":                               "T1070.003",
		"Linux Shadow File Credential Dump":                         "T1003.008",
		"Linux systemd Service Persistence":                         "T1543.002",
		"Linux Shell Init Persistence (.bashrc / profile)":          "T1546.004",
		"Container Escape to Host":                                  "T1611",
		"Container Image Build on Host":                             "T1612",
		"Linux Destructive Disk/File Wipe":                          "T1485",
		"SSH Private Key Access (Linux)":                            "T1552.004",
		"SSH Private Key File Read":                                 "T1552.004",
		"Malicious AppleScript Execution (osascript)":               "T1059.002",
		"macOS Launch Agent/Daemon Persistence":                     "T1543.001",
		"macOS Keychain Credential Access":                          "T1555.001",
		"macOS Gatekeeper Bypass":                                   "T1553.001",
		"macOS Login Item Persistence":                              "T1547.015",
		"macOS Screen Capture (screencapture)":                      "T1113",
		"Domain Trust Discovery":                                    "T1482",
		"Domain Account Discovery":                                  "T1087.002",
		"Remote System and Domain Controller Discovery":             "T1018",
		"Domain Group Discovery":                                    "T1069.002",
		"DNS Tunneling and C2":                                      "T1071.004",
		"FTP/TFTP Exfiltration Channel":                             "T1071.002",
		"AS-REP Roasting":                                           "T1558.004",
		"Shell History Credential Search":                           "T1552.003",
		"Golden or Silver Ticket Forging":                           "T1558.001",
		"Pass-the-Hash":                                             "T1550.002",
		"Network Share Discovery":                                   "T1135",
		"Group Policy Discovery":                                    "T1615",
		"Cloud Service and IAM Discovery":                           "T1526",
		"Cloud Infrastructure Discovery":                            "T1580",
		"Cloud Storage Object Discovery":                            "T1619",
		"Mail Protocol Exfiltration":                                "T1071.003",
		"Cloud Account Creation":                                    "T1136.003",
		"Additional Cloud Credentials":                              "T1098.001",
		"Additional Cloud Roles":                                    "T1098.003",
		"Cloud Logging Tampering":                                   "T1562.008",
		"Cloud Firewall Opening":                                    "T1562.007",
		"Cloud Compute Infrastructure Modification":                 "T1578",
		"Impacket Remote Execution":                                 "T1021.002",
		"AD CS Certificate Abuse":                                   "T1649",
		"Authentication Coercion":                                   "T1187",
		"Kerberos Brute-Force and User Enumeration":                 "T1110",
		"Follina MSDT Code Execution":                               "T1218",
		"Email Forwarding Rule":                                     "T1114.003",
		"Office Application Startup Persistence":                    "T1137",
		"Control Panel Item Execution":                              "T1218.002",
	}

	got := map[string]string{}
	for _, ruleYAML := range builtinSigmaRules {
		title, tech := builtinPrimaryTech(ruleYAML)
		if title == "" {
			t.Errorf("builtin Sigma rule has no title: %.60q", ruleYAML)
			continue
		}
		if tech == "" {
			t.Errorf("builtin Sigma rule %q has no attack.t* technique tag", title)
		}
		got[title] = tech
	}

	for title, exp := range want {
		g, ok := got[title]
		if !ok {
			t.Errorf("expected builtin rule %q not found (renamed/removed?)", title)
			continue
		}
		if g != exp {
			t.Errorf("builtin %q primary technique = %q, want %q — check the tag ORDER (most-specific technique must be first)", title, g, exp)
		}
	}
}

// TestNewCoverageRulesMatch verifies the coverage rules added 2026-06-22 actually
// fire end-to-end (flatten → alias → builtin Sigma) on a representative malicious
// command line, so a rule that compiles but silently never matches is caught.
func TestNewCoverageRulesMatch(t *testing.T) {
	e := NewSigmaEvaluator()
	LoadBuiltinRules(e)

	cases := []struct {
		title, image, cmd string
	}{
		{"MSBuild Proxy Execution", `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe`, `MSBuild.exe C:\Users\Public\payload.csproj`},
		{"Image File Execution Options Debugger Persistence", `C:\Windows\system32\reg.exe`, `reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /d cmd.exe /f`},
		{"Windows Defender Tampering via Registry", `C:\Windows\system32\reg.exe`, `reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f`},
		{"Hidden File or Directory via attrib", `C:\Windows\system32\attrib.exe`, `attrib +h +s C:\Users\Public\evil.exe`},
		{"Broad File Permission Change via icacls/takeown", `C:\Windows\system32\icacls.exe`, `icacls C:\Windows\Temp\x /grant Everyone:F /T /C`},
		{"Domain Account Creation via net.exe", `C:\Windows\system32\net.exe`, `net user evilop P@ss123 /add /domain`},
		{"DCSync Credential Replication", `C:\Tools\mimikatz.exe`, `mimikatz.exe "lsadump::dcsync /domain:corp.local /user:krbtgt"`},
		{"Windows Credential Manager Access", `C:\Windows\system32\cmdkey.exe`, `cmdkey /list`},
		{"RDP Enabled or Session Hijack", `C:\Windows\system32\tscon.exe`, `tscon 2 /dest:rdp-tcp#0`},
		{"WinRM Lateral Movement (winrs / PowerShell Remoting)", `C:\Windows\system32\winrs.exe`, `winrs -r:srv01 cmd /c whoami`},
		{"Internal Proxy via netsh portproxy", `C:\Windows\system32\netsh.exe`, `netsh interface portproxy add v4tov4 listenport=3389 connectaddress=10.0.0.5 connectport=3389`},
		{"Regsvcs/Regasm Proxy Execution", `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\RegAsm.exe`, `RegAsm.exe /U C:\Users\Public\evil.dll`},
		{"Root Certificate Installation via certutil", `C:\Windows\system32\certutil.exe`, `certutil -addstore -f root C:\Users\Public\evil.cer`},
		{"XSL Script Processing Proxy Execution", `C:\Windows\system32\wbem\wmic.exe`, `wmic os get /format:"C:\Users\Public\evil.xsl"`},
		{"Clipboard Data Collection", `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `powershell -c "Get-Clipboard | Out-File c:\temp\clip.txt"`},
		{"Screen Capture via CopyFromScreen / Screenshot Tool", `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `powershell -c "$g.CopyFromScreen(0,0,0,0,$bmp.Size)"`},
		{"Keylogging via Windows Hook / Async Key State", `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `powershell -c "Add-Type ...; [K]::GetAsyncKeyState($k)"`},
		{"Email Collection via Mailbox Export", `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `powershell -c "New-MailboxExportRequest -Mailbox ceo -FilePath \\srv\share\ceo.pst"`},
		{"LSA Secrets Dump", `C:\Windows\system32\reg.exe`, `reg save HKLM\SECURITY C:\temp\sec.hive`},
		{"Cached Domain Credentials Dump", `C:\Tools\mimikatz.exe`, `mimikatz.exe "lsadump::cache"`},
		{"Private Key Harvesting", `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `powershell -c "Get-ChildItem -Recurse -Filter id_rsa C:\Users"`},
		{"LLMNR/NBT-NS Poisoning Tool (Responder/Inveigh)", `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `powershell -c "Invoke-Inveigh -ConsoleOutput Y"`},
		{"Group Policy Preferences Password Retrieval", `C:\Windows\system32\findstr.exe`, `findstr /S /I cpassword \\dc\SYSVOL\domain\Policies\*.xml`},
		{"System Process Name From Non-Standard Path (Masquerading)", `C:\Users\Public\svchost.exe`, `svchost.exe -k netsvcs`},
		{"Hidden Window Execution", `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `powershell.exe -nop -WindowStyle Hidden -enc ABC`},
		{"NTFS Alternate Data Stream Manipulation", `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `powershell -c "Set-Content -Path a.txt -Stream evil -Value $b"`},
		{"Timestomping (File Time Modification)", `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `powershell -c "(gi f).LastWriteTime = '2009-01-01'"`},
		{"Windows Event Logging Disabled", `C:\Windows\system32\wevtutil.exe`, `wevtutil sl Security /e:false`},
		{"SSH Lateral Movement with Inline Credentials", `C:\Tools\plink.exe`, `plink.exe -ssh -pw P@ss123 admin@10.0.0.5 whoami`},
		{"DCOM Lateral Movement", `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `powershell -c "[type]::GetTypeFromProgID('MMC20.Application','10.0.0.5')"`},
		{"Pass-the-Ticket (Kerberos Ticket Injection)", `C:\Tools\rubeus.exe`, `rubeus.exe ptt /ticket:doit.kirbi`},
		{"Access Token Manipulation", `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `powershell -c "Invoke-TokenManipulation -CreateProcess cmd.exe"`},
		{"Cryptocurrency Mining (Resource Hijacking)", `C:\Users\Public\xmrig.exe`, `xmrig.exe -o stratum+tcp://pool.minexmr.com:4444 --donate-level 1`},
		{"Disk Wipe / Destruction", `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `powershell -c "Clear-Disk -Number 1 -RemoveData -Confirm:$false"`},
		{"Account Access Removal", `C:\Windows\system32\net.exe`, `net user administrator /delete`},
		{"Sudo Privilege Escalation via Shell Escape (GTFOBins)", `/usr/bin/sudo`, `sudo find / -exec /bin/sh \; -quit`},
		{"Clear Linux Command History", `/bin/bash`, `bash -c "unset HISTFILE; history -c"`},
		{"Linux Shadow File Credential Dump", `/bin/cat`, `cat /etc/shadow`},
		{"Linux systemd Service Persistence", `/usr/bin/systemd-run`, `systemd-run --on-active=60 /tmp/evil.sh`},
		{"Linux Shell Init Persistence (.bashrc / profile)", `/usr/bin/tee`, `tee -a /home/user/.bashrc`},
		{"Container Escape to Host", `/usr/bin/nsenter`, `nsenter --target 1 --mount --uts --ipc --net --pid -- bash`},
		{"Container Image Build on Host", `/usr/bin/docker`, `docker build -t evil:latest -f Dockerfile .`},
		{"Linux Destructive Disk/File Wipe", `/usr/sbin/mkfs.ext4`, `mkfs.ext4 /dev/sdb1`},
		{"SSH Private Key Access (Linux)", `/bin/cat`, `cat /home/user/.ssh/id_rsa`},
		{"Malicious AppleScript Execution (osascript)", `/usr/bin/osascript`, `osascript -e 'do shell script "id"'`},
		{"macOS Launch Agent/Daemon Persistence", `/bin/launchctl`, `launchctl load -w /Library/LaunchDaemons/com.evil.plist`},
		{"macOS Keychain Credential Access", `/usr/bin/security`, `security dump-keychain -d login.keychain`},
		{"macOS Gatekeeper Bypass", `/usr/sbin/spctl`, `spctl --master-disable`},
		{"macOS Login Item Persistence", `/usr/bin/osascript`, `osascript -e 'tell application "System Events" to make login item at end'`},
		{"macOS Screen Capture (screencapture)", `/usr/sbin/screencapture`, `screencapture -x /tmp/s.png`},
	}
	for _, c := range cases {
		env := map[string]any{"type": "process", "data": map[string]any{
			"process": map[string]any{"command_line": c.cmd, "image_path": c.image, "process_name": c.image, "action": "create"},
		}}
		flat := flattenNormalizedEvent(env)
		hit := false
		for _, m := range e.EvaluateEvent(flat) {
			if m.RuleTitle == c.title {
				hit = true
				break
			}
		}
		if !hit {
			t.Errorf("rule %q did not match its trigger command (cmd=%q)", c.title, c.cmd)
		}
	}
}

// TestMimikatzModulePatternsMatch guards against the YAML trailing-colon trap: a Sigma
// list value ending in ":" (e.g. `- lsadump::`) parses as a MAP, not a string, so the
// pattern silently never matches. The fix quotes such values. This test fires the
// Mimikatz rule on a RENAMED binary (Image lacks "mimikatz"), so it can only match via
// the CommandLine module patterns — exactly the path that was dead.
func TestMimikatzModulePatternsMatch(t *testing.T) {
	e := NewSigmaEvaluator()
	LoadBuiltinRules(e)

	cases := []struct{ name, cmd string }{
		{"lsadump", `m.exe lsadump::sam`},
		{"kerberos", `m.exe kerberos::ptt ticket.kirbi`},
		{"sekurlsa-regression", `m.exe sekurlsa::logonpasswords`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			env := map[string]any{"type": "process", "data": map[string]any{
				"process": map[string]any{
					"command_line": c.cmd,
					"image_path":   `C:\tools\m.exe`, // intentionally NOT "mimikatz"
					"process_name": "m.exe",
					"action":       "create",
				},
			}}
			flat := flattenNormalizedEvent(env)
			hit := false
			for _, m := range e.EvaluateEvent(flat) {
				if m.RuleTitle == "Mimikatz Credential Dumping Tool Detected" {
					hit = true
					break
				}
			}
			if !hit {
				t.Errorf("Mimikatz rule did not match command module pattern (cmd=%q) — "+
					"check that the CommandLine|contains values ending in '::' are quoted", c.cmd)
			}
		})
	}
}

// TestMasqueradeRuleNotLogic guards the "not legit" path of the masquerade rule
// (T1036.003): a system-process name from a non-standard path MUST fire, but the same
// name from System32 must NOT — exercising the SigmaEvaluator's `not` operator.
func TestMasqueradeRuleNotLogic(t *testing.T) {
	e := NewSigmaEvaluator()
	LoadBuiltinRules(e)
	const title = "System Process Name From Non-Standard Path (Masquerading)"

	fires := func(image string) bool {
		flat := map[string]any{"image_path": image, "process_name": image, "action": "create"}
		addPipelineSigmaAliases(flat)
		for _, m := range e.EvaluateEvent(flat) {
			if m.RuleTitle == title {
				return true
			}
		}
		return false
	}

	if !fires(`C:\Users\Public\svchost.exe`) {
		t.Error("masquerade rule did not fire on svchost.exe from a non-standard path")
	}
	if fires(`C:\Windows\System32\svchost.exe`) {
		t.Error("masquerade rule FALSE-POSITIVE on legitimate System32 svchost.exe (not-logic broken)")
	}
}

// TestWebShellRuleMatch verifies the Web Shell rule fires on a web-server parent
// spawning a shell. parent_process is what parentResolver injects from the ppid
// cache; addPipelineSigmaAliases maps it to ParentImage (and image_path→Image),
// mirroring the live pipeline.
func TestWebShellRuleMatch(t *testing.T) {
	e := NewSigmaEvaluator()
	LoadBuiltinRules(e)
	flat := map[string]any{
		"image_path":     `C:\Windows\System32\cmd.exe`,
		"process_name":   "cmd.exe",
		"parent_process": "w3wp.exe",
		"action":         "create",
	}
	addPipelineSigmaAliases(flat)
	hit := false
	for _, m := range e.EvaluateEvent(flat) {
		if strings.Contains(m.RuleTitle, "Web Shell") {
			hit = true
		}
	}
	if !hit {
		t.Errorf("Web Shell rule did not match w3wp.exe → cmd.exe (ParentImage=%v Image=%v)", flat["ParentImage"], flat["Image"])
	}
}
