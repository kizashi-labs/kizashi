package detection

import "testing"

// TestDefenseEvasionCredFire verifies that the Defense-Evasion "classic gap" and
// Credential-Access deep-dive builtin rules actually FIRE against representative
// telemetry through the real flatten+alias+evaluate path — not merely that they
// carry the right ATT&CK tag order (which TestBuiltinSigmaPrimaryTechnique alone
// guards). This closes the "static coverage ≠ live detection" gap the coverage
// audit repeatedly warns about (docs/ATT&CK検知カバレッジ監査.md): a rule can own
// the technique tag yet never match because a field name or condition is off.
//
// Events use the agent's snake_case telemetry keys (image_path/command_line/…)
// exactly as the AlertPipeline receives them; addPipelineSigmaAliases performs the
// Sigma-field aliasing the pipeline applies before evaluation.
func TestDefenseEvasionCredFire(t *testing.T) {
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
		// ── Defense Evasion — classic gaps ────────────────────────────────
		{
			// T1036.003 — a core system-process name running from a non-system path.
			"System Process Name From Non-Standard Path (Masquerading)",
			map[string]interface{}{
				"type":         "process",
				"image_path":   `C:\Users\Public\svchost.exe`,
				"command_line": `svchost.exe -k netsvcs`,
			},
		},
		{
			// T1564.003 — real command lines mix case; the evaluator lowercases contains.
			"Hidden Window Execution",
			map[string]interface{}{
				"type":         "process",
				"image_path":   `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
				"command_line": `powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand ZQBjAGgA`,
			},
		},
		{
			// T1564.004 — writing into an NTFS alternate data stream.
			"NTFS Alternate Data Stream Manipulation",
			map[string]interface{}{
				"type":         "process",
				"image_path":   `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
				"command_line": `powershell -Command "Set-Content -Path C:\temp\host.txt -Stream evil -Value calc.exe"`,
			},
		},
		{
			// T1070.006 — PowerShell timestomping via LastWriteTime assignment.
			"Timestomping (File Time Modification)",
			map[string]interface{}{
				"type":         "process",
				"image_path":   `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
				"command_line": `powershell (Get-Item C:\temp\evil.dll).LastWriteTime = "01/01/2001 09:00"`,
			},
		},
		{
			// T1562.002 — auditpol disabling a category.
			"Windows Event Logging Disabled",
			map[string]interface{}{
				"type":         "process",
				"image_path":   `C:\Windows\System32\auditpol.exe`,
				"command_line": `auditpol /set /category:* /success:disable /failure:disable`,
			},
		},
		{
			// T1562.002 — wevtutil disabling a log (contains|all: sl + /e:false).
			"Windows Event Logging Disabled",
			map[string]interface{}{
				"type":         "process",
				"image_path":   `C:\Windows\System32\wevtutil.exe`,
				"command_line": `wevtutil sl Security /e:false`,
			},
		},

		// ── Credential Access — deep dive ─────────────────────────────────
		{
			// T1003.004 — saving the SECURITY hive (contains|all: save + hklm\security).
			"LSA Secrets Dump",
			map[string]interface{}{
				"type":         "process",
				"image_path":   `C:\Windows\System32\reg.exe`,
				"command_line": `reg save HKLM\SECURITY C:\temp\sec.hive`,
			},
		},
		{
			// T1003.005 — cached domain credential dump via mimikatz.
			"Cached Domain Credentials Dump",
			map[string]interface{}{
				"type":         "process",
				"image_path":   `C:\Users\Public\mk.exe`,
				"command_line": `mk.exe "lsadump::cache" exit`,
			},
		},
		{
			// T1552.004 — recursive harvest of private key files.
			"Private Key Harvesting",
			map[string]interface{}{
				"type":         "process",
				"image_path":   `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
				"command_line": `Get-ChildItem -Path C:\Users -Recurse -Include id_rsa,*.pem`,
			},
		},
		{
			// T1557.001 — LLMNR/NBT-NS poisoning via Inveigh.
			"LLMNR/NBT-NS Poisoning Tool (Responder/Inveigh)",
			map[string]interface{}{
				"type":         "process",
				"image_path":   `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
				"command_line": `powershell Invoke-Inveigh -ConsoleOutput Y -NBNS Y`,
			},
		},
		{
			// T1134 — token impersonation tradecraft.
			"Access Token Manipulation",
			map[string]interface{}{
				"type":         "process",
				"image_path":   `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
				"command_line": `powershell Invoke-TokenManipulation -ImpersonateUser -Username NT AUTHORITY\SYSTEM`,
			},
		},
		{
			// T1003.006 — DCSync credential replication.
			"DCSync Credential Replication",
			map[string]interface{}{
				"type":         "process",
				"image_path":   `C:\Users\Public\mk.exe`,
				"command_line": `mk.exe "lsadump::dcsync /domain:corp.local /user:krbtgt"`,
			},
		},
		{
			// T1555.004 — Windows Credential Manager enumeration.
			"Windows Credential Manager Access",
			map[string]interface{}{
				"type":         "process",
				"image_path":   `C:\Windows\System32\cmdkey.exe`,
				"command_line": `cmdkey /list`,
			},
		},
		{
			// T1552.006 — Group Policy Preferences cpassword retrieval.
			"Group Policy Preferences Password Retrieval",
			map[string]interface{}{
				"type":         "process",
				"image_path":   `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
				"command_line": `powershell Get-GPPPassword -Verbose`,
			},
		},

		// ── Lateral Movement — high-value holes ───────────────────────────
		{
			// T1021.004 — SSH lateral movement with inline credentials.
			"SSH Lateral Movement with Inline Credentials",
			map[string]interface{}{
				"type":         "process",
				"image_path":   `C:\tools\plink.exe`,
				"command_line": `plink -ssh -pw Passw0rd! admin@10.0.0.5`,
			},
		},
		{
			// T1021.003 — DCOM lateral movement via MMC20.Application.
			"DCOM Lateral Movement",
			map[string]interface{}{
				"type":         "process",
				"image_path":   `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
				"command_line": `powershell [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","10.0.0.5"))`,
			},
		},
		{
			// T1550.003 — Pass-the-Ticket / Kerberos ticket injection.
			"Pass-the-Ticket (Kerberos Ticket Injection)",
			map[string]interface{}{
				"type":         "process",
				"image_path":   `C:\Users\Public\mk.exe`,
				"command_line": `mk.exe "kerberos::ptt C:\temp\admin.kirbi"`,
			},
		},

		// ── Impact — high-value holes ─────────────────────────────────────
		{
			// T1496 — cryptocurrency mining / resource hijacking.
			"Cryptocurrency Mining (Resource Hijacking)",
			map[string]interface{}{
				"type":         "process",
				"image_path":   `C:\ProgramData\xmrig.exe`,
				"command_line": `xmrig -o stratum+tcp://pool.minexmr.com:4444 --donate-level 1`,
			},
		},
		{
			// T1561 — disk wipe / destruction via diskpart clean.
			"Disk Wipe / Destruction",
			map[string]interface{}{
				"type":         "process",
				"image_path":   `C:\Windows\System32\diskpart.exe`,
				"command_line": `diskpart /s C:\temp\clean.txt`,
			},
		},
		{
			// T1531 — account access removal (net user /delete).
			"Account Access Removal",
			map[string]interface{}{
				"type":         "process",
				"image_path":   `C:\Windows\System32\net.exe`,
				"command_line": `net user helpdesk /delete`,
			},
		},
	}

	for _, tc := range cases {
		if !fires(tc.ruleTitle, tc.event) {
			t.Errorf("rule %q did not fire on representative telemetry: %v", tc.ruleTitle, tc.event)
		}
	}
}
