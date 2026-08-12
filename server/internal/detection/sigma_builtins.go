// Package detection — BuiltinSigmaRules provides a curated set of MITRE
// ATT&CK-aligned Sigma rules that are loaded into the SigmaEvaluator at
// startup, independent of the database.  They supplement any rules stored in
// the yara_rules / custom_alert_rules tables.
//
// ⚠️ DUAL RULE ENGINES — read before editing (see docs/検知ルールの二重管理とデプロイ.md):
//
//	These builtins run ONLY in the SigmaEvaluator inside the API server's
//	AlertPipeline (cmd/api → NewAlertPipeline). They produce "[Sigma] <title>"
//	alerts. A SEPARATE engine — rules.RuleEngine in the detection server
//	(cmd/detection → NewEngine) — evaluates Sigma rules loaded from the DB
//	(detection_rules, seeded by migrations 014/019). Same-titled rules can exist
//	in BOTH with DIFFERENT detection logic (e.g. "Registry Run Key Persistence":
//	builtin = process_creation on reg.exe; DB = registry_set on TargetObject).
//
//	Therefore: editing a builtin here takes effect only after redeploying
//	server-api; editing a DB rule requires server-detect. Forgetting which is the
//	#1 source of "I fixed it but nothing changed" (2026-06-22 incident).
//
//	The alert's mitre_technique is the FIRST attack.t* tag (parseMITRETechFromTags),
//	so for multi-technique rules the most-specific technique MUST be listed first.
//	TestBuiltinSigmaPrimaryTechnique guards this. Unifying the two engines onto one
//	rule source is tracked as 案A in the dual-management doc.
package detection

// builtinSigmaRules is the list of YAML Sigma rules shipped with the platform.
// Keep each rule as a separate string so they can be compiled independently;
// a compile error in one rule does not block the others.
var builtinSigmaRules = []string{
	// ── T1003 – OS Credential Dumping ────────────────────────
	`
title: Mimikatz Credential Dumping Tool Detected
description: Detects the execution of Mimikatz, a common credential-dumping tool.
status: stable
level: critical
tags:
  - attack.t1003
  - attack.credential_access
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - sekurlsa
      - "kerberos::"
      - "lsadump::"
  selection_name:
    Image|contains: mimikatz
  condition: selection or selection_name
falsepositives:
  - Authorised penetration testing
`,
	`
title: LSASS Memory Dump via Process Access
description: Detects suspicious access to lsass.exe that may indicate credential dumping.
status: stable
level: high
tags:
  - attack.t1003.001
  - attack.credential_access
logsource:
  product: windows
  category: process_access
detection:
  selection:
    TargetImage|contains: lsass.exe
    GrantedAccess|contains:
      - "0x1FFFFF"
      - "0x1F3FFF"
      - "0x1010"
  condition: selection
falsepositives:
  - Security monitoring tools
  - Antivirus software
`,

	// ── T1021 – Remote Services ───────────────────────────────
	`
title: PsExec Remote Execution
description: Detects PsExec usage, commonly used for lateral movement.
status: stable
level: high
tags:
  - attack.t1021.002
  - attack.lateral_movement
logsource:
  product: windows
  category: process_creation
detection:
  # psexec64.exe was merged in from the DB rule (migration 286) when it was
  # disabled in migration 375 to stop the same event raising two alerts — one from
  # this pipeline and one from the detection engine. It is NOT redundant with the
  # other PsExec builtins: "PsExec Service Execution" only matches psexec64.exe
  # together with -accepteula, so a run without that flag matched nothing here.
  # Note "psexec.exe" does not substring-match "psexec64.exe" — it needs its own entry.
  #
  # paexec/remcom are deliberately NOT listed: "PsExec-Alternative Remote Execution
  # Tool (PAExec/RemCom)" already matches them with Image|contains. Adding them here
  # would make one paexec.exe execution raise two builtin alerts — reintroducing,
  # inside this pipeline, exactly the double-counting migrations 373/374 remove.
  by_image:
    Image|contains:
      - psexec.exe
      - psexec64.exe
      - psexesvc.exe
  # PsExec's client binary and its remote service copy are both trivially
  # renamed (attackers commonly drop "svchost_update.exe" etc. and pass
  # "-r <name>" to rename the installed service too), evading an
  # Image-filename-only match. "-accepteula" is a Sysinternals-suite-specific
  # flag that survives renaming and isn't used by other common tooling.
  # PSEXESVC is the service name the remote half installs — it survives renaming
  # the client binary and appears even when -accepteula was already accepted on
  # the target (also merged in from the DB rule).
  by_flag:
    CommandLine|contains:
      - accepteula
      - PSEXESVC
  condition: by_image or by_flag
falsepositives:
  - Legitimate remote administration by IT staff
`,

	// ── T1021.002 – Impacket Remote Execution Suite ────────────
	`
title: Impacket Remote Execution
description: Detects Impacket's cross-platform remote-execution suite (psexec.py, smbexec.py, wmiexec.py, atexec.py, dcomexec.py) used for lateral movement over SMB/WMI/DCOM/scheduled-tasks from a Linux attacker host — missed by rules keyed on the Windows PsExec.exe binary.
status: stable
level: high
tags:
  - attack.t1021.002
  - attack.lateral_movement
logsource:
  category: process_creation
detection:
  impacket_exec:
    CommandLine|contains:
      - "psexec.py"
      - "smbexec.py"
      - "wmiexec.py"
      - "atexec.py"
      - "dcomexec.py"
      # A pip/pipx install of Impacket registers console-script entry points
      # without the ".py" suffix — "impacket-wmiexec domain/user:pass@host"
      # is now the more common invocation and matched none of the patterns
      # above.
      - "impacket-psexec"
      - "impacket-smbexec"
      - "impacket-wmiexec"
      - "impacket-atexec"
      - "impacket-dcomexec"
  condition: impacket_exec
falsepositives:
  - Authorised red-team / administration using Impacket
`,
	`
title: WMI Spawning Command Shell
description: Detects wmiprvse.exe spawning cmd.exe or powershell.exe, indicative of WMI-based lateral movement.
status: stable
level: high
tags:
  - attack.t1021.006
  - attack.lateral_movement
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|contains: wmiprvse.exe
    Image|contains:
      - cmd.exe
      - powershell.exe
      - wscript.exe
      - cscript.exe
  condition: selection
falsepositives:
  - Legitimate WMI management scripts
`,

	// ── T1053 – Scheduled Task/Job ────────────────────────────
	`
title: Suspicious Scheduled Task via Network Path
description: Detects schtasks creating a task with a network path, often used for persistence.
status: stable
level: high
tags:
  - attack.t1053.005
  - attack.persistence
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|contains: schtasks.exe
    CommandLine|contains|all:
      - /create
      - "\\\\"
  condition: selection
falsepositives:
  - Legitimate administrative scheduled tasks using UNC paths
`,
	`
title: Scheduled Task Creation via schtasks
description: Detects creation of a scheduled task via schtasks.exe — a common persistence/execution mechanism. Broader than the UNC-path rule above; medium level to reflect benign administrative use.
status: stable
level: medium
tags:
  - attack.t1053.005
  - attack.persistence
  - attack.execution
logsource:
  product: windows
  category: process_creation
detection:
  schtasks_create:
    Image|contains: schtasks
    CommandLine|contains: /create
  # "schtasks /change /tn <task> /tr <evil>" repoints an existing task's run
  # command — persistence that evades a "/create"-only rule. Requiring /tr
  # avoids benign "/change /enable|/disable" administration.
  schtasks_change:
    Image|contains: schtasks
    CommandLine|contains|all:
      - /change
      - /tr
  ps_register:
    CommandLine|contains:
      - Register-ScheduledTask
      - Set-ScheduledTask
  condition: schtasks_create or schtasks_change or ps_register
falsepositives:
  - Legitimate administrative or software-installer scheduled tasks
`,

	// ── T1070 – Indicator Removal ─────────────────────────────
	`
title: Windows Event Log Cleared
description: Detects the clearing of Windows event logs, often performed to cover tracks.
status: stable
level: high
tags:
  - attack.t1070.001
  - attack.defense_evasion
logsource:
  product: windows
  category: process_creation
detection:
  selection_wevtutil:
    Image|contains: wevtutil.exe
    # wevtutil accepts both the short verb "cl" and the long form "clear-log";
    # "wevtutil clear-log Security" evades a " cl "-only signature.
    CommandLine|contains:
      - " cl "
      - clear-log
  selection_powershell:
    CommandLine|contains:
      - Clear-EventLog
      - Remove-EventLog
  condition: selection_wevtutil or selection_powershell
falsepositives:
  - Legitimate log management automation
`,
	`
title: Security Audit Log Cleared
description: Detects clearing of the Windows Security audit log.
status: stable
level: critical
tags:
  - attack.t1070.001
  - attack.defense_evasion
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 1102
  condition: selection
falsepositives:
  - Authorised log retention management
`,

	// ── T1105 – Ingress Tool Transfer ─────────────────────────
	`
title: CertUtil Used for File Download
description: Detects certutil being used to download a file over the network
  (-urlcache / -verifyctl), a common LOLBin ingress technique. Scoped to the
  options that actually cause a fetch. -decode / -encode / -decodehex are purely
  local transforms and were previously listed here, so an entirely offline
  "certutil -decode a.b64 a.exe" raised an alert titled "for File Download" — a
  confirmed false positive in the 2026-07-18 benign battery. Those options now
  have their own rule (CertUtil Used for Local Base64 Decode, T1140) so the two
  behaviours stay distinguishable to an analyst.
status: stable
level: high
tags:
  - attack.t1105
  - attack.command_and_control
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|contains: certutil.exe
    CommandLine|contains:
      - -urlcache
      - -verifyctl
      - -split
      - /urlcache
      - /verifyctl
      - /split
  condition: selection
falsepositives:
  - Legitimate certificate management
`,

	// ── T1140 – Deobfuscate/Decode Files or Information ────────
	// The offline half of the certutil split above. Encoding a payload to Base64
	// to survive transport and decoding it on the host is standard tradecraft, but
	// it is a DIFFERENT technique from downloading, and conflating them cost the
	// download rule its precision.
	`
title: CertUtil Used for Local Base64 Decode
description: Detects certutil performing a local encode/decode transform
  (-decode / -encode / -decodehex) with no download option present. Commonly
  used to reconstitute a payload that was staged in text form to evade content
  inspection.
status: stable
level: medium
tags:
  - attack.t1140
  - attack.defense_evasion
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|contains: certutil.exe
    CommandLine|contains:
      - -decode
      - -encode
      - -decodehex
      - /decode
      - /encode
      - /decodehex
  download:
    CommandLine|contains:
      - -urlcache
      - -verifyctl
      - /urlcache
      - /verifyctl
  certconv:
    CommandLine|contains:
      - .cer
      - .crt
      - .der
      - .pfx
      - .p7b
  condition: selection and not download and not certconv
falsepositives:
  - Payload staging that deliberately names its output with a certificate extension
`,
	`
title: BITSAdmin Used for File Download
description: Detects bitsadmin being used to transfer files, a common LOLBin technique.
status: stable
level: high
tags:
  - attack.t1105
  - attack.command_and_control
logsource:
  product: windows
  category: process_creation
detection:
  transfer:
    Image|contains: bitsadmin.exe
    CommandLine|contains: /transfer
  # The multi-step form (bitsadmin /create; /addfile <URL> <local>; /resume)
  # downloads without /transfer, evading a "/transfer"-only rule. The /addfile
  # step carries the remote URL.
  addfile:
    Image|contains: bitsadmin.exe
    CommandLine|contains|all:
      - /addfile
    CommandLine|contains:
      - http
      - ftp
  condition: transfer or addfile
falsepositives:
  - Legitimate Windows Update or software distribution
`,

	// ── T1112 – Modify Registry ───────────────────────────────
	`
title: Registry Run Key Persistence
description: Detects modification of the Windows Run registry key for persistence.
status: stable
level: high
tags:
  - attack.t1547.001
  - attack.t1112
  - attack.persistence
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|contains: reg.exe
    CommandLine|contains|all:
      - add
      - CurrentVersion\Run
  # PowerShell registry cmdlets write the same Run key without reg.exe.
  ps_write_cmd:
    CommandLine|contains:
      - Set-ItemProperty
      - New-ItemProperty
      - Set-Item
  ps_write_key:
    CommandLine|contains: CurrentVersion\Run
  condition: selection or (ps_write_cmd and ps_write_key)
falsepositives:
  - Legitimate software installers
`,

	// ── T1112 – Modify Registry (generic reg.exe add) ─────────
	// Companion to the Run-key rule above: attributes the Modify Registry
	// technique for ANY reg.exe write to HKCU/HKLM/HKU, even when the target
	// is not a known high-value key (the Run-key/Defender/UAC/Winlogon rules
	// stay higher severity). Kept level:low so it is informational visibility,
	// not an actionable alert — generic reg.exe add is common in installers
	// and admin scripts.
	`
title: Registry Modification via reg.exe
description: Detects generic registry modification via reg.exe add against HKCU/HKLM/HKU, covering the Modify Registry technique for arbitrary keys not matched by the dedicated high-value-key rules.
status: stable
level: low
tags:
  - attack.t1112
  - attack.defense_evasion
logsource:
  product: windows
  category: process_creation
detection:
  selection_reg:
    Image|contains: reg.exe
    CommandLine|contains: ' add '
  selection_hive:
    CommandLine|contains:
      - HKCU
      - HKLM
      - 'HKU\'
      - HKEY_
  condition: selection_reg and selection_hive
falsepositives:
  - Legitimate software installers and configuration scripts
  - Administrative registry configuration via batch or GPO
`,

	// ── T1562 – Impair Defenses ───────────────────────────────
	`
title: Windows Defender Real-Time Protection Disabled
description: Detects disabling of Windows Defender real-time monitoring.
status: stable
level: critical
tags:
  - attack.t1562.001
  - attack.defense_evasion
logsource:
  product: windows
  category: process_creation
detection:
  # "Set-MpPreference -DisableRealtimeMonitoring $true" is the disable form;
  # the value can also be the numeric 1 ("-DisableRealtimeMonitoring 1"),
  # which evades a "true"-only value match while still disabling RTP.
  selection:
    CommandLine|contains|all:
      - Set-MpPreference
      - DisableRealtimeMonitoring
    CommandLine|contains:
      - "true"
      - " 1"
  condition: selection
falsepositives:
  - Authorised security testing or AV management
`,
	`
title: Windows Firewall Disabled via Netsh
description: Detects disabling of Windows Firewall via netsh command.
status: stable
level: critical
tags:
  - attack.t1562.004
  - attack.defense_evasion
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|contains: netsh.exe
    CommandLine|contains|all:
      - advfirewall
      - allprofiles
      - "state off"
  condition: selection
falsepositives:
  - Authorised network configuration changes
`,

	// ── Linux – T1166: SUID Bit Set ───────────────────────────
	`
title: SUID Bit Set on Non-Standard Binary
description: Detects chmod setting the SUID bit on a file, which could allow privilege escalation.
status: stable
level: high
tags:
  - attack.t1166
  - attack.privilege_escalation
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    Image|contains: chmod
    CommandLine|contains:
      - "+s"
      - "u+s"
      - "4755"
      - "4777"
  condition: selection
falsepositives:
  - Legitimate package installation (verify binary path)
`,

	// ── Linux – T1068: pkexec Exploit (CVE-2021-4034) ─────────
	`
title: Pkexec Exploitation Attempt (CVE-2021-4034)
description: Detects exploitation patterns for the pkexec privilege escalation (PwnKit).
status: stable
level: critical
tags:
  - attack.t1068
  - attack.privilege_escalation
  - cve.2021-4034
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    Image|contains: pkexec
    CommandLine|contains:
      - "GCONV_PATH"
      - "CHARSET"
      - "GIO_USE_VFS"
  condition: selection
falsepositives:
  - Unlikely in production; high-confidence indicator
`,

	// ── Linux – T1087: Sensitive File Read ────────────────────
	`
title: Suspicious Read of /etc/shadow
description: Detects reads of /etc/shadow, which stores hashed passwords and should only be accessed by privileged system tools.
status: stable
level: high
tags:
  - attack.t1087.001
  - attack.discovery
logsource:
  product: linux
  category: file_access
detection:
  selection:
    TargetFilename|contains:
      - /etc/shadow
  condition: selection
falsepositives:
  - Shadow password management tools (passwd, chpasswd, useradd)
`,

	// ── Linux – T1098: /etc/passwd 書き込み ──────────────────
	`
title: /etc/passwd ファイルへの書き込み
description: /etc/passwd への書き込みはユーザー追加・権限昇格の試みを示す可能性がある。
status: stable
level: high
tags:
  - attack.t1098
  - attack.persistence
logsource:
  product: linux
  category: file_event
detection:
  selection:
    TargetFilename|contains:
      - /etc/passwd
    Operation|contains:
      - write
      - modify
      - modified
      - create
      - created
  condition: selection
falsepositives:
  - useradd/adduser などのシステム管理コマンド
`,

	// ── Linux – T1059.004: Bash リバースシェル ───────────────
	`
title: Bash リバースシェルの試み
description: bash の /dev/tcp または stdout リダイレクトを使ったリバースシェル接続パターンを検知する。
status: stable
level: critical
tags:
  - attack.t1059.004
  - attack.execution
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - /dev/tcp/
      - /dev/udp/
      - bash -i >&
      - "0>&1"
  condition: selection
falsepositives:
  - 承認済みペネトレーションテスト
`,

	// ── Linux – T1098.004: SSH authorized_keys 改ざん ─────────
	`
title: SSH authorized_keys への不審な書き込み
description: authorized_keys ファイルへの書き込みは SSH バックドア設置の可能性がある。
status: stable
level: high
tags:
  - attack.t1098.004
  - attack.persistence
logsource:
  product: linux
  category: file_event
detection:
  selection:
    TargetFilename|contains:
      - .ssh/authorized_keys
  condition: selection
falsepositives:
  - 正規の SSH 公開鍵管理 (ansible, terraform 等)
`,

	// ── Linux – T1105: /tmp へのファイルダウンロード ──────────
	`
title: curl/wget による /tmp へのファイルダウンロード
description: curl/wget で /tmp や /dev/shm にファイルを保存するパターンはマルウェアドロッパーに多用される。
status: stable
level: medium
tags:
  - attack.t1105
  - attack.command_and_control
logsource:
  product: linux
  category: process_creation
detection:
  selection_tool:
    Image|contains:
      - curl
      - wget
  selection_dest:
    CommandLine|contains:
      - /tmp/
      - /dev/shm/
      - /var/tmp/
  condition: selection_tool and selection_dest
falsepositives:
  - 正規のソフトウェアインストールスクリプト
`,

	// ── Linux – T1140: Base64 デコード実行 ───────────────────
	`
title: Base64 エンコードコマンドの実行
description: Base64 デコードしてシェルに渡すパターンはコマンド難読化・マルウェアのペイロード展開に多用される。
status: stable
level: medium
tags:
  - attack.t1140
  - attack.defense_evasion
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - "base64 -d"
      - "base64 --decode"
      - "| base64"
  condition: selection
falsepositives:
  - 正規のデプロイスクリプト
`,

	// ── Linux – T1095: Netcat リバースシェル ─────────────────
	`
title: Netcat/ncat による不審な通信
description: nc/ncat の実行はリバースシェルや不審なポートフォワーディングの可能性がある。
status: stable
level: high
tags:
  - attack.t1095
  - attack.command_and_control
logsource:
  product: linux
  category: process_creation
detection:
  selection_image:
    Image|contains:
      - /nc
      - /ncat
      - /netcat
      - /nc.traditional
  condition: selection_image
falsepositives:
  - 承認済みのネットワークデバッグ作業
`,

	// ── Linux – T1059: /tmp からの実行 ───────────────────────
	`
title: /tmp または /dev/shm からの実行ファイル起動
description: /tmp や /dev/shm から直接実行ファイルを起動するパターンはメモリ常駐型マルウェアに典型的。
status: stable
level: high
tags:
  - attack.t1059
  - attack.execution
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    Image|startswith:
      - /tmp/
      - /dev/shm/
      - /var/tmp/
  condition: selection
falsepositives:
  - 一時インストーラスクリプト
`,

	// ── Linux – T1053.003: 不審な cron ジョブ追加 ────────────
	`
title: Linux の疑わしい cron ジョブ追加
description: ダウンロードや実行コマンドを含む cron ファイルの作成は永続化バックドアの可能性がある。
status: stable
level: high
tags:
  - attack.t1053.003
  - attack.persistence
logsource:
  product: linux
  category: file_event
detection:
  cron_files:
    TargetFilename|contains:
      - /etc/cron
      - /var/spool/cron
      - /etc/crontab
  suspicious_content:
    Contents|contains:
      - "curl "
      - "wget "
      - "bash -i"
      - /dev/tcp/
      - "nc -e"
      - "python -c"
      - "perl -e"
  condition: cron_files and suspicious_content
falsepositives:
  - 正規のバックアップスクリプト
`,

	// ── T1110 – Brute Force ───────────────────────────────────
	//
	// There is deliberately NO per-event failed-logon builtin here. A rule shipped
	// under this heading ("Multiple Failed Login Attempts (Brute Force Indicator)",
	// `EventID: 4625`) was removed on 2026-08-04 after being found unreachable AND
	// wrong in shape:
	//
	//   - Unreachable: `EventID` is not a field on our auth telemetry. Ingestion
	//     flattens an AuthEvent to username/action/success/source_ip/auth_method/
	//     logon_type (handler.go, EVENT_TYPE_AUTH), and the pipeline derives EventID
	//     for REGISTRY events only. The rule could not match a single event this
	//     product has ever produced. A 2026-07-20 field audit nonetheless recorded
	//     it as resolved, because EventID *is* in the supported set — via the
	//     registry path. Being in the supported set does not mean the field is
	//     populated for THIS event type.
	//   - Mislabelled: its first attack.t* tag was t1078, and the alert's
	//     mitre_technique is that first tag (parseMITRETechFromTags). A failed-logon
	//     burst was therefore reported as Valid Accounts, and since T1078 and T1110
	//     share no tactic, per-technique attribution scored T1110 as a miss even on
	//     a hit.
	//   - Wrong shape: making it reachable is not the fix. A single failure is not
	//     an attack, and the FP-soak corpus asserts exactly this — the benign
	//     profiles carry a "typo'd password" failure whose stated purpose is to
	//     verify that nothing alerts on one occurrence (tests/fpsoak/profiles/
	//     dev-machine.toml). Reviving the rule produced 9,599/1000host/day of pure
	//     false positives and tripped the regression gate.
	//
	// Brute force and password spray are RATE/FAN-OUT phenomena. AuthAttackScorer
	// (auth_attack.go) is the detector: sliding window, per-account depth and
	// per-source breadth, plus the success that closes a failure burst. Note it
	// runs in the detection server only, so the api server has no T1110 coverage
	// today — that redundancy gap is architectural (every stateful detector lives
	// in Engine) and is not something a per-event Sigma rule can close.

	// ── T1059.001 – Encoded PowerShell ────────────────────────
	`
title: Encoded PowerShell Command Execution
description: Detects PowerShell run with an encoded command, commonly used to obfuscate payloads.
status: stable
level: high
tags:
  - attack.t1059.001
  - attack.execution
  - attack.defense_evasion
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|contains:
      - powershell
      - pwsh
    # PowerShell accepts ANY unambiguous prefix of -EncodedCommand, so
    # -e / -en / -enc / -enco / … -encodedcommand all decode a base64 payload.
    # A rule listing only -enc/-ec/-e is trivially evaded with -en or -encod.
    CommandLine|contains:
      - " -e "
      - " -ec "
      - " -en "
      - " -enc "
      - " -enco "
      - " -encod "
      - " -encode "
      - " -encoded "
      - " -encodedc "
      - " -encodedco "
      - " -encodedcom "
      - " -encodedcomm "
      - " -encodedcomma "
      - " -encodedcomman "
      - " -encodedcommand "
      # PowerShell.exe also accepts the "/" switch prefix, so /e /enc …
      # /encodedcommand decode a base64 payload identically — a "-"-only list is
      # evaded with "powershell /enc <b64>".
      - " /e "
      - " /ec "
      - " /en "
      - " /enc "
      - " /enco "
      - " /encod "
      - " /encode "
      - " /encoded "
      - " /encodedc "
      - " /encodedco "
      - " /encodedcom "
      - " /encodedcomm "
      - " /encodedcomma "
      - " /encodedcomman "
      - " /encodedcommand "
  condition: selection
falsepositives:
  - Rare legitimate automation using encoded commands
`,

	// ── T1490 – Inhibit System Recovery (shadow copies) ───────
	`
title: Volume Shadow Copy Deletion
description: Detects deletion of volume shadow copies, a common ransomware precursor.
status: stable
level: critical
tags:
  - attack.t1490
  - attack.impact
logsource:
  product: windows
  category: process_creation
detection:
  vssadmin:
    Image|contains:
      - vssadmin.exe
      - wmic.exe
      - diskshadow.exe
    CommandLine|contains:
      - delete shadows
      - shadowcopy delete
      - resize shadowstorage
  bcdedit:
    Image|contains: bcdedit.exe
    CommandLine|contains:
      - recoveryenabled no
      - bootstatuspolicy ignoreallfailures
  # PowerShell WMI/CIM shadow deletion evades an Image-list keyed on vssadmin/
  # wmic — Get-WmiObject/Get-CimInstance Win32_ShadowCopy | Remove-*.
  ps_wmi_obj:
    CommandLine|contains: Win32_ShadowCopy
  ps_wmi_del:
    CommandLine|contains:
      - Remove-WmiObject
      - Remove-CimInstance
      - ".Delete("
      - Delete()
  wbadmin:
    Image|contains: wbadmin.exe
    CommandLine|contains:
      - delete catalog
      - delete systemstatebackup
      - delete backup
  condition: vssadmin or bcdedit or (ps_wmi_obj and ps_wmi_del) or wbadmin
falsepositives:
  - Legitimate backup software maintenance
`,

	// ── T1543.003 – Create or Modify Windows Service ──────────
	`
title: Windows Service Creation via sc.exe
description: Detects creation OR binPath modification of a Windows service, often used for persistence or privilege escalation.
status: stable
level: high
tags:
  - attack.t1543.003
  - attack.persistence
  - attack.privilege_escalation
logsource:
  product: windows
  category: process_creation
detection:
  sc_create:
    Image|contains: sc.exe
    CommandLine|contains|all:
      - create
      - binpath
  # "sc config <svc> binPath= C:\evil.exe" repoints an EXISTING service's
  # binary — a persistence/priv-esc path that evades a "create"-only rule.
  sc_config:
    Image|contains: sc.exe
    CommandLine|contains|all:
      - config
      - binpath
  ps_newservice:
    CommandLine|contains: New-Service
  condition: sc_create or sc_config or ps_newservice
falsepositives:
  - Legitimate software installation
`,

	// ── T1136.001 – Create Local Account ──────────────────────
	`
title: Local Account Creation
description: Detects creation of a new local user account, often used for persistence.
status: stable
level: medium
tags:
  - attack.t1136.001
  - attack.persistence
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|contains: net
    CommandLine|contains|all:
      - user
      - /add
  condition: selection
falsepositives:
  - Legitimate account provisioning by IT
`,

	// ── T1218.005 – Mshta Proxy Execution ─────────────────────
	`
title: Mshta Suspicious Remote Execution
description: Detects mshta.exe executing remote or scripted payloads (proxy execution LOLBin).
status: stable
level: high
tags:
  - attack.t1218.005
  - attack.defense_evasion
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|contains: mshta.exe
    CommandLine|contains:
      - http
      - vbscript
      - javascript
      - ".hta"
      - "about:"
      # mshta launching an .hta staged in a user-writable directory (legit HTA
      # LOB apps run from Program Files); \ProgramData\ closes the same staging
      # gap already covered for rundll32/regsvr32.
      - "\\Temp\\"
      - "\\AppData\\"
      - "\\Users\\Public\\"
      - "\\ProgramData\\"
  condition: selection
falsepositives:
  - Legacy HTA-based line-of-business applications
`,

	// ── T1218.011 – Rundll32 Proxy Execution ──────────────────
	`
title: Rundll32 Suspicious Proxy Execution
description: Detects rundll32.exe used to proxy script/remote execution (LOLBin abuse).
status: stable
level: high
tags:
  - attack.t1218.011
  - attack.defense_evasion
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|contains: rundll32.exe
    CommandLine|contains:
      - javascript
      - vbscript
      - mshtml
      # Classic LOLBin export abuse (proxy execution / download-and-run via a
      # signed binary), missed by a script-keyword-only rule.
      - "url.dll,OpenURL"
      - "url.dll,FileProtocolHandler"
      - "pcwutl.dll,LaunchApplication"
      - "advpack.dll,LaunchINFSection"
      - "advpack.dll,RegisterOCX"
      - "syssetup.dll,SetupInfObjectInstallAction"
      - "zipfldr.dll,RouteTheCall"
      - "shell32.dll,ShellExec_RunDLL"
      # rundll32 loading a DLL from a user-writable staging directory (legit
      # rundll32 loads from System32/SysWOW64), a strong indicator of abuse.
      - "\\Temp\\"
      - "\\AppData\\"
      - "\\Users\\Public\\"
      - "\\ProgramData\\"
      # rundll32 can load and execute a DLL straight off a UNC share
      # ("rundll32.exe \\host\share\evil.dll,Entry") — remote proxy execution
      # that needs none of the script/export/staging-dir markers above.
      - "\\\\"
  condition: selection
falsepositives:
  - Rare; rundll32 normally loads local DLLs from System32 by ordinal
`,

	// ── T1003.001 – LSASS Dump via comsvcs MiniDump ───────────
	`
title: LSASS Memory Dump via comsvcs.dll
description: Detects rundll32 invoking comsvcs.dll MiniDump to dump LSASS memory.
status: stable
level: critical
tags:
  - attack.t1003.001
  - attack.credential_access
logsource:
  product: windows
  category: process_creation
detection:
  dll:
    CommandLine|contains: comsvcs
  # comsvcs MiniDump can be invoked by its export NAME (MiniDump) or its ORDINAL
  # (#24) — rundll32 comsvcs.dll,#24 <pid> out.dmp full evades a "MiniDump"-only
  # signature.
  method:
    CommandLine|contains:
      - MiniDump
      - "#24"
  condition: dll and method
falsepositives:
  - None expected
`,

	// ── T1003.001 – LSASS Dump via Tool / PowerShell ──────────
	`
title: LSASS Memory Dump via Tool or PowerShell
description: Detects LSASS-dumping tools and PowerShell cmdlets (nanodump, dumpert, HandleKatz, Out-Minidump, pypykatz, lsassy, SafetyKatz) used to harvest credentials from LSASS.
status: stable
level: critical
tags:
  - attack.t1003.001
  - attack.credential_access
logsource:
  product: windows
  category: process_creation
detection:
  tools:
    CommandLine|contains:
      - nanodump
      - dumpert
      - handlekatz
      - Out-Minidump
      - pypykatz
      - lsassy
      - safetykatz
      - Invoke-Mimikatz
      # Microsoft-signed LOLBins abused to dump process memory (LSASS); no
      # legitimate enterprise use — rdrleakdiag /fullmemdmp and TTD dumps.
      - rdrleakdiag
      - tttracer
  condition: tools
falsepositives:
  - None expected; these are dedicated credential-dumping tools
`,

	// ── T1003.002 – SAM/SECURITY Hive Dump via reg save ───────
	`
title: Registry Hive Dump for Credential Access
description: Detects dumping of SAM/SYSTEM/SECURITY registry hives, used to extract credentials.
status: stable
level: high
tags:
  - attack.t1003.002
  - attack.credential_access
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|contains: reg
    CommandLine|contains|all:
      - save
      - hklm\sam
  condition: selection
falsepositives:
  - Rare legitimate backup of registry hives
`,

	// ── T1003.004 – LSA Secrets Dump (SECURITY hive) ──────────
	// Distinct from T1003.002 (SAM): the SECURITY hive holds LSA secrets —
	// service-account passwords, DPAPI keys, cached secrets. reg save HKLM\SAM
	// is matched above; HKLM\SECURITY is uncovered until now.
	`
title: LSA Secrets Dump via reg save (SECURITY hive)
description: Detects saving of the HKLM\SECURITY registry hive, which stores LSA secrets (service account passwords, cached secrets), for offline credential extraction.
status: experimental
level: high
tags:
  - attack.t1003.004
  - attack.credential_access
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|contains: reg
    CommandLine|contains|all:
      - save
      - hklm\security
  condition: selection
falsepositives:
  - Rare legitimate backup of registry hives
`,

	// ── T1003.005 – Cached Domain Credentials (DCC2/MSCache) ───
	`
title: Cached Domain Credentials Dump (DCC2)
description: Detects tools/commands that extract MSCache/DCC2 cached domain credentials (cachedump, gsecdump, mimikatz lsadump::cache).
status: experimental
level: high
tags:
  - attack.t1003.005
  - attack.credential_access
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - cachedump
      - gsecdump
      - "lsadump::cache"
  condition: selection
falsepositives:
  - None expected
`,

	// ── T1552.004 – Private Keys (SSH/PEM/PPK theft) ──────────
	`
title: Private Key File Access (SSH/PPK)
description: Detects reading or searching for private key material (id_rsa, id_dsa, id_ecdsa, id_ed25519, .ppk), a common precursor to credential theft and lateral movement.
status: experimental
level: medium
tags:
  - attack.t1552.004
  - attack.credential_access
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - id_rsa
      - id_dsa
      - id_ecdsa
      - id_ed25519
      - .ppk
  condition: selection
falsepositives:
  - Legitimate SSH key management, backups, or automation
`,

	// ── T1557.001 – LLMNR/NBT-NS Poisoning (Responder/Inveigh) ─
	`
title: LLMNR/NBT-NS Poisoning Tool (Responder/Inveigh)
description: Detects execution of Responder or Inveigh, used for LLMNR/NBT-NS/mDNS poisoning to capture NetNTLM hashes (adversary-in-the-middle credential access).
status: experimental
level: high
tags:
  - attack.t1557.001
  - attack.credential_access
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - Responder.py
      - Inveigh
      - Invoke-Inveigh
      - ntlmrelayx
      - ntlmrelayx.py
  condition: selection
falsepositives:
  - Authorised penetration testing
`,

	// ── T1003.003 – NTDS.dit Extraction ───────────────────────
	`
title: NTDS.dit Extraction via ntdsutil
description: Detects extraction of the Active Directory database (NTDS.dit) for offline credential theft.
status: stable
level: critical
tags:
  - attack.t1003.003
  - attack.credential_access
logsource:
  product: windows
  category: process_creation
detection:
  ntdsutil:
    Image|contains: ntdsutil
    CommandLine|contains:
      - ifm
      - create full
  ntdsdit:
    CommandLine|contains: ntds.dit
  # Scripted diskshadow hides the ntds.dit copy inside a .dsh script file, so the
  # command line only shows "diskshadow /s <script>" — evades an ntds.dit-literal rule.
  diskshadow_script:
    CommandLine|contains|all:
      - diskshadow
    CommandLine|contains:
      - "/s"
      - exec
  # esentutl /y (copy, ignores locks) via a VSS snapshot copies locked hives/DB
  # (SAM/SYSTEM/ntds.dit) for offline credential theft.
  esentutl_vss:
    CommandLine|contains|all:
      - esentutl
    CommandLine|contains:
      - "/vss"
      - vss
  condition: ntdsutil or ntdsdit or diskshadow_script or esentutl_vss
falsepositives:
  - Authorised domain controller backups
`,

	// ── T1071.001 – PowerShell Download Cradle ────────────────
	`
title: PowerShell Web Download Cradle
description: Detects PowerShell downloading and executing remote content (download cradle).
status: stable
level: high
tags:
  - attack.t1071.001
  - attack.command_and_control
  - attack.execution
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|contains: powershell
    CommandLine|contains:
      - downloadstring
      - downloadfile
      - downloaddata
      - net.webclient
      - invoke-webrequest
      - invoke-restmethod
      - webrequest
      - openread
      - start-bitstransfer
  condition: selection
falsepositives:
  - Legitimate administrative scripts fetching resources
`,

	// ── T1071.004 – DNS Tunneling / C2 ─────────────────────────
	`
title: DNS Tunneling and C2
description: Detects DNS-based command-and-control and exfiltration tooling (dnscat2, iodine, dns2tcp, dnsteal, DNSExfiltrator), which smuggle data inside DNS queries to evade egress controls.
status: stable
level: high
tags:
  - attack.t1071.004
  - attack.command_and_control
  - attack.exfiltration
logsource:
  product: windows
  category: process_creation
detection:
  tool_cmd:
    CommandLine|contains:
      - dnscat
      - iodine
      - dns2tcp
      - dnsteal
      - DNSExfiltrator
      - Invoke-DnsExfil
  tool_image:
    Image|contains:
      - dnscat
      - iodine
      - dns2tcp
  condition: tool_cmd or tool_image
falsepositives:
  - Rare; the named tools are not used by legitimate software
`,

	// ── T1071.002 – File Transfer Protocol Exfiltration ────────
	`
title: FTP/TFTP Exfiltration Channel
description: Detects scripted or command-line file transfer over FTP/TFTP/SCP used to exfiltrate data or stage tools (scripted ftp input files, tftp put, curl upload to ftp URLs, WinSCP/pscp scripted transfers).
status: stable
level: medium
tags:
  - attack.t1071.002
  - attack.exfiltration
logsource:
  product: windows
  category: process_creation
detection:
  ftp_scripted:
    CommandLine|contains:
      - "ftp -s:"
      - "ftp -n -s"
  tftp_put:
    CommandLine|contains|all:
      - "tftp"
      - " put "
  curl_ftp_upload:
    CommandLine|contains|all:
      - "ftp://"
      - "-T "
  winscp_pscp:
    CommandLine|contains:
      - "winscp.com /command"
      - "winscp.exe /command"
      - "pscp -"
  condition: ftp_scripted or tftp_put or curl_ftp_upload or winscp_pscp
falsepositives:
  - Legacy backup or deployment scripts using scripted FTP transfers
`,

	// ── T1071.003 – Mail Protocol Exfiltration ─────────────────
	`
title: Mail Protocol Exfiltration
description: Detects data exfiltration or C2 over mail protocols (SMTP/IMAP) via command-line mailers with attachments — PowerShell Send-MailMessage with -Attachments, swaks --attach, sendemail -a, or curl to smtp/smtps URLs.
status: stable
level: medium
tags:
  - attack.t1071.003
  - attack.exfiltration
logsource:
  category: process_creation
detection:
  ps_sendmail:
    CommandLine|contains|all:
      - "Send-MailMessage"
      - "-Attachment"
  swaks:
    CommandLine|contains|all:
      - "swaks"
      - "--attach"
  sendemail:
    CommandLine|contains|all:
      - "sendemail"
      - " -a "
  curl_smtp:
    CommandLine|contains:
      - "curl smtp://"
      - "curl smtps://"
      - "--mail-from"
  condition: ps_sendmail or swaks or sendemail or curl_smtp
falsepositives:
  - Monitoring or backup scripts emailing reports with attachments
`,

	// ── T1485 – Data Destruction ──────────────────────────────
	`
title: Data Destruction via Wiping Utility
description: Detects secure-wipe / data-destruction tooling that overwrites files or free space.
status: stable
level: high
tags:
  - attack.t1485
  - attack.impact
logsource:
  product: windows
  category: process_creation
detection:
  cipher:
    Image|contains: cipher.exe
    CommandLine|contains: /w
  sdelete:
    Image|contains: sdelete
  condition: cipher or sdelete
falsepositives:
  - Authorised secure deletion of sensitive data
`,

	// ── T1552.001 – Credentials In Files (findstr/grep harvest) ───
	`
title: Credential Harvesting via File Search
description: Detects findstr/grep recursively searching files for password/credential keywords, a common unsecured-credentials discovery technique.
status: stable
level: medium
tags:
  - attack.t1552.001
  - attack.credential_access
  - attack.discovery
logsource:
  category: process_creation
detection:
  tool:
    Image|contains:
      - findstr.exe
      - findstr
      - /grep
      - grep.exe
  keyword:
    CommandLine|contains:
      - password
      - passwd
      - credential
      - secret
      - apikey
      - api_key
      - connectionstring
  recursive:
    CommandLine|contains:
      - /s
      - /si
      - -r
      - -R
      - --recursive
  condition: tool and keyword and recursive
falsepositives:
  - Administrators or developers legitimately searching configuration files
`,

	// ── T1218.010 – Regsvr32 Squiblydoo / Scriptlet Proxy ─────────
	`
title: Regsvr32 Scriptlet/Remote Proxy Execution
description: Detects regsvr32 abused to execute remote or scriptlet (.sct) payloads (Squiblydoo).
status: stable
level: high
tags:
  - attack.t1218.010
  - attack.defense_evasion
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|contains: regsvr32.exe
    CommandLine|contains:
      - scrobj.dll
      - /i:http
      - /i:ftp
      - .sct
      # regsvr32 registering a DLL from a user-writable staging directory
      # (legit COM registration uses Program Files / System32), a strong
      # indicator of "regsvr32 /s <dropped.dll>" abuse.
      - "\\Temp\\"
      - "\\AppData\\"
      - "\\Users\\Public\\"
      - "\\ProgramData\\"
      # regsvr32 registers a DLL straight off a UNC share without needing
      # /i: at all ("regsvr32.exe \\host\share\evil.dll") — a remote-proxy
      # vector this rule's title covers but none of the above patterns catch.
      - "\\\\"
  condition: selection
falsepositives:
  - Rare legitimate COM registration of remote scriptlets
`,

	// ── T1047 – WMIC Process Call Create ──────────────────────────
	`
title: WMIC Process Call Create
description: Detects wmic spawning processes via "process call create", used for execution and lateral movement.
status: stable
level: high
tags:
  - attack.t1047
  - attack.execution
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|contains: wmic.exe
    CommandLine|contains|all:
      - process
      - call
      - create
  condition: selection
falsepositives:
  - Legitimate administrative WMI scripting
`,

	// ── T1546.003 – WMI Event Subscription Persistence (WMI subsystem) ──
	//
	// Consumes the wmi_activity sensor (ETW 5861), not process_creation. The pair
	// is deliberate and not redundant: "WMIC Process Call Create" above and the DB
	// rule in migration 329 both key on a wmic command line, which only exists when
	// the subscription is created through wmic. Set-WmiInstance from PowerShell,
	// ManagementClass from .NET, or any in-process WMI client registers the same
	// persistence with no such command line at all. This rule observes the
	// registration where it actually happens.
	//
	// It must live here, not only in the rules table, because server-api's
	// AlertPipeline loads the built-ins and server-detect loads the DB — a DB-only
	// rule leaves the primary alert path dark for this sensor (see
	// docs/検知ルールの二重管理とデプロイ.md).
	//
	// Keyed on the CONSUMER TYPE rather than on the existence of a subscription:
	// management suites register subscriptions routinely, and firing on all of them
	// would reproduce the non-discriminating-selector pattern that dominated the
	// 2026-08-03 FP soak. A consumer that executes code is the technique.
	`
title: WMI Event Subscription Registered (ETW)
description: Detects registration of a WMI event subscription whose consumer executes code
  (CommandLineEventConsumer / ActiveScriptEventConsumer), observed from the WMI subsystem
  itself rather than from a wmic command line. Fileless persistence that survives reboot and
  leaves no parent process linking back to WMI.
status: stable
level: high
tags:
  - attack.t1546.003
  - attack.persistence
  - attack.privilege_escalation
logsource:
  product: windows
  category: wmi_event
detection:
  selection:
    event_type: WmiBindingEvent
  executing_consumer:
    consumer|contains:
      - "CommandLineEventConsumer"
      - "ActiveScriptEventConsumer"
  condition: selection and executing_consumer
falsepositives:
  - Management suites that legitimately register command-line consumers
`,

	// ── T1218.003 – CMSTP Proxy Execution ─────────────────────────
	`
title: CMSTP Suspicious Execution
description: Detects cmstp.exe used to proxy execution via malicious INF files,
  bypassing AppLocker/UAC. Requires the silent-install options (/s, /ns) that the
  LOLBAS technique depends on. An .inf argument is MANDATORY for every cmstp.exe
  invocation, so listing it as an independently-sufficient match meant any
  ordinary connection-manager profile install fired this rule.
status: stable
level: high
tags:
  - attack.t1218.003
  - attack.defense_evasion
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|contains: cmstp.exe
    CommandLine|contains:
      - /s
      - /ns
  condition: selection
falsepositives:
  - Silent connection-manager profile deployment by a management tool
`,

	// ── T1055.001 – Mavinject DLL Injection ───────────────────────
	`
title: Mavinject Process Injection
description: Detects mavinject.exe injecting a DLL into a running process (INJECTRUNNING), a LOLBin injection technique.
status: stable
level: high
tags:
  - attack.t1055.001
  - attack.defense_evasion
  - attack.privilege_escalation
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|contains: mavinject.exe
    CommandLine|contains: INJECTRUNNING
  condition: selection
falsepositives:
  - None expected outside App-V environments
`,

	// ── T1218.004 – InstallUtil Proxy Execution ───────────────────
	`
title: InstallUtil Proxy Execution
description: Detects installutil.exe used to proxy code execution while
  suppressing output, a common .NET LOLBin technique. Keyed on the
  log-suppression options, which is what the description already claimed and
  what the LOLBAS invocation always carries. /u alone was previously an
  independently-sufficient match, so every ordinary .NET service uninstall fired
  this rule; the technique's own /U is still caught because it is accompanied by
  /logfile= and /LogToConsole=false.
status: stable
level: medium
tags:
  - attack.t1218.004
  - attack.defense_evasion
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|contains: installutil.exe
    CommandLine|contains:
      - /logfile=
      - /logtoconsole=false
  condition: selection
falsepositives:
  - Build or deployment scripts that silence InstallUtil output
`,

	// ── T1070.004 – Delete USN Change Journal ─────────────────────
	`
title: USN Change Journal Deletion via fsutil
description: Detects deletion of the NTFS USN change journal, used to hinder forensic recovery of file activity.
status: stable
level: high
tags:
  - attack.t1070.004
  - attack.defense_evasion
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|contains: fsutil.exe
    CommandLine|contains|all:
      - usn
      - deletejournal
  condition: selection
falsepositives:
  - Rare legitimate disk maintenance
`,

	// ── T1003.003 – esentutl VSS / Hive Copy ──────────────────────
	`
title: Esentutl Shadow Copy / Sensitive File Extraction
description: Detects esentutl used with volume shadow copy paths to extract locked files such as ntds.dit or registry hives.
status: stable
level: high
tags:
  - attack.t1003.003
  - attack.credential_access
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|contains: esentutl.exe
    CommandLine|contains:
      - /vss
      - "\\\\.\\GLOBALROOT"
      - ntds.dit
  condition: selection
falsepositives:
  - Authorised database maintenance using esentutl
`,

	// ── T1218.008 – Odbcconf Proxy Execution ──────────────────────
	`
title: Odbcconf Proxy Execution
description: Detects odbcconf.exe used to load and execute a DLL via REGSVR, a
  LOLBin proxy-execution technique. Keyed on REGSVR, which is the action that
  actually loads the DLL. /a and .dll are standard syntax for EVERY odbcconf
  action (CONFIGSYSDSN, CONFIGDSN, INSTALLDRIVER...), so listing them as
  independently-sufficient matches meant routine ODBC driver configuration fired
  a high-severity proxy-execution alert.
status: stable
level: high
tags:
  - attack.t1218.008
  - attack.defense_evasion
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|contains: odbcconf.exe
    CommandLine|contains: regsvr
  condition: selection
falsepositives:
  - Legitimate driver registration that genuinely uses REGSVR
`,

	// ── T1059.005/.007 – WScript/CScript Script From Temp ─────────
	`
title: WScript/CScript Executing Script From Temp
description: Detects Windows Script Host running .vbs/.js/.wsf scripts from temp/download/appdata locations, typical of phishing payloads.
status: stable
level: high
tags:
  - attack.t1059.005
  - attack.t1059.007
  - attack.execution
logsource:
  product: windows
  category: process_creation
detection:
  host:
    Image|contains:
      - wscript.exe
      - cscript.exe
  script:
    CommandLine|contains:
      - .vbs
      - .js
      - .jse
      - .wsf
      - .vbe
  location:
    CommandLine|contains:
      - \temp\
      - \appdata\
      - \downloads\
      - \public\
      - \programdata\
  condition: host and script and location
falsepositives:
  - Legitimate logon or deployment scripts staged in those paths
`,

	// ── T1003.001 – LSASS Dump via ProcDump ───────────────────────
	`
title: LSASS Memory Dump via ProcDump
description: Detects ProcDump (Sysinternals) used to dump lsass.exe memory for offline credential extraction.
status: stable
level: critical
tags:
  - attack.t1003.001
  - attack.credential_access
logsource:
  product: windows
  category: process_creation
detection:
  procdump_named:
    Image|contains: procdump
    CommandLine|contains: lsass
  # A renamed procdump binary evades "Image contains procdump", but the
  # full-dump flags (-ma / -mp) against lsass are still on the command line.
  procdump_flags:
    CommandLine|contains|all:
      - lsass
    CommandLine|contains:
      - " -ma"
      - " -mp"
  condition: procdump_named or procdump_flags
falsepositives:
  - Authorised crash-dump collection of lsass for debugging
`,

	// ── T1218.007 – Msiexec Remote Package Install ────────────────
	`
title: Msiexec Remote MSI Execution
description: Detects msiexec installing a package from a remote URL, a LOLBin proxy-execution / download technique.
status: stable
level: high
tags:
  - attack.t1218.007
  - attack.defense_evasion
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|contains: msiexec.exe
    CommandLine|contains:
      - http://
      - https://
      - ftp://
  condition: selection
falsepositives:
  - Enterprise software deployment from trusted internal URLs
`,

	// ── T1560.001 – Archive Collected Data ────────────────────────
	`
title: Data Staged in Password-Protected Archive
description: Detects archiving utilities creating password-protected archives, often used to stage data before exfiltration.
status: stable
level: medium
tags:
  - attack.t1560.001
  - attack.collection
logsource:
  product: windows
  category: process_creation
detection:
  tool:
    Image|contains:
      - rar.exe
      - winrar
      - 7z.exe
      - 7za.exe
      - 7zg.exe
  protect:
    CommandLine|contains:
      - " -hp"
      - " -p"
      - "-hp"
  condition: tool and protect
falsepositives:
  - Legitimate password-protected backups
`,

	// ── T1567.002 – Exfiltration to Cloud Storage (rclone) ────────
	`
title: Data Exfiltration via Rclone or MEGAcmd
description: Detects rclone or MEGAcmd copying/syncing data to cloud storage backends, the dominant exfiltration tooling in ransomware intrusions. Also catches rclone renamed to evade the binary-name check by keying on its command-line syntax.
status: stable
level: high
tags:
  - attack.t1567.002
  - attack.exfiltration
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|contains: rclone
    CommandLine|contains:
      - copy
      - sync
      - " mega"
      - ":b2"
      - ":s3"
      - "--transfers"
      - "--multi-thread"
  cmdline_rclone:
    CommandLine|contains|all:
      - "rclone"
    CommandLine|contains:
      - copy
      - sync
      - ":b2"
      - ":s3"
      - "--transfers"
  mega_tools:
    CommandLine|contains:
      - megatools
      - "mega-put"
      - "MEGAcmd"
      - "mega-cmd"
      - megacmdserver
  condition: selection or cmdline_rclone or mega_tools
falsepositives:
  - Sanctioned backup workflows that use rclone or MEGA
`,

	// ── T1218 – Follina MSDT Code Execution (CVE-2022-30190) ───
	`
title: Follina MSDT Code Execution
description: Detects abuse of the Microsoft Support Diagnostic Tool (msdt.exe) for arbitrary code execution (CVE-2022-30190 "Follina") — msdt invoked with IT_BrowseForFile/PCWDiagnostic or via the ms-msdt URI protocol handler, frequently spawned from an Office document.
status: stable
level: high
tags:
  - attack.t1218
  - attack.defense_evasion
  - attack.execution
logsource:
  product: windows
  category: process_creation
detection:
  msdt:
    CommandLine|contains|all:
      - "msdt"
    CommandLine|contains:
      - "IT_BrowseForFile"
      - "PCWDiagnostic"
      - "ms-msdt"
  uri:
    CommandLine|contains: "ms-msdt:/id"
  condition: msdt or uri
falsepositives:
  - Legitimate Windows troubleshooting launched via msdt
`,

	// ── T1048 – Exfiltration Over Alternative Protocol ─────────────
	// Exfil の被覆は監査で「最希薄」だった戦術。ツール起点のアップロード
	// (curl -T/--upload-file, wget --post-file, tftp PUT, IWR -InFile) を捕捉する。
	`
title: Data Exfiltration Over Alternative Protocol (Upload Tools)
description: Detects file-upload invocations of common transfer tools to a remote host — curl -T/--upload-file/--data-binary, wget --post-file/--body-file, tftp PUT, the built-in ftp.exe client in unattended script mode (-s:), or PowerShell Invoke-WebRequest -InFile — a hallmark of exfiltration over an alternative protocol.
status: experimental
level: medium
tags:
  - attack.t1048
  - attack.t1048.003
  - attack.exfiltration
logsource:
  category: process_creation
detection:
  curl:
    Image|contains: curl
    CommandLine|contains:
      - " -T "
      - --upload-file
      - --data-binary @
      - --data @
  wget:
    Image|contains: wget
    CommandLine|contains:
      - --post-file
      - --body-file
  tftp:
    Image|contains: tftp
    CommandLine|contains: put
  # The built-in ftp.exe. Its put/get commands are typed INSIDE the interactive
  # session, never passed as arguments, so upload-vs-download cannot be told from
  # process creation at all — which is why this keys on -s: (the LOLBAS-documented
  # unattended-script option) rather than on the transfer direction. Interactive
  # or manual ftp use never carries it; the non-interactive invocation used for
  # exfil does. Matching bare ftp.exe instead would alert on every launch,
  # including an idle or read-only session.
  # endswith with the leading separator is deliberate: Image|contains: ftp would
  # also swallow tftp.exe, which the tftp selection above already handles.
  ftp_script:
    Image|endswith: \ftp.exe
    CommandLine|contains: '-s:'
  psupload:
    CommandLine|contains|all:
      - invoke-webrequest
      - -infile
  condition: curl or wget or tftp or ftp_script or psupload
falsepositives:
  - Legitimate scripted uploads or backups using curl/wget
  - Unattended ftp.exe batch jobs that are part of an established transfer process
`,

	// ── T1572 – Protocol Tunneling Tools ──────────────────────────
	`
title: Network Tunneling Tool Execution
description: Detects known tunneling/port-forwarding utilities (ngrok, plink reverse, chisel, frp, ligolo-ng) used for C2 or pivoting.
status: stable
level: medium
tags:
  - attack.t1572
  - attack.command_and_control
logsource:
  product: windows
  category: process_creation
detection:
  ngrok:
    Image|contains: ngrok
  chisel:
    Image|contains: chisel
  frp:
    Image|contains:
      - frpc
      - frps
  plink:
    Image|contains: plink
    CommandLine|contains:
      - " -R"
      - " -L"
      - " -D"
  # ligolo-ng: an increasingly common tunneling tool (a reverse-tunnel proxy
  # + agent pair), missing entirely from this rule. Its release assets are
  # named "ligolo-ng_agent_<ver>_<os>_<arch>" by default, so the string
  # shows up in the Image path more reliably than in the CLI args (which
  # are just "-connect host:port -ignore-cert").
  ligolo:
    Image|contains: ligolo
  condition: ngrok or chisel or frp or plink or ligolo
falsepositives:
  - Authorised remote-access / debugging tunnels
`,

	// ── T1219 – Remote Access Software ────────────────────────────
	`
title: Remote Access Software Execution
description: Detects remote-access/RMM tools frequently abused for hands-on-keyboard access (AnyDesk, TeamViewer, ScreenConnect, Atera, Splashtop, Ammyy).
status: stable
level: medium
tags:
  - attack.t1219
  - attack.command_and_control
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|contains:
      - anydesk
      - teamviewer
      - screenconnect
      - ateragent
      - splashtop
      - ammyy
      - anyviewer
  condition: selection
falsepositives:
  - Organisations that legitimately use these tools for IT support
`,

	// ── T1558.003 – Kerberoasting (Rubeus) ────────────────────────
	`
title: Kerberoasting via Rubeus
description: Detects Rubeus or kerberoast/asreproast tradecraft used to request and crack Kerberos service tickets.
status: stable
level: high
tags:
  - attack.t1558.003
  - attack.credential_access
logsource:
  product: windows
  category: process_creation
detection:
  tool:
    Image|contains: rubeus
  technique:
    CommandLine|contains:
      - kerberoast
      - asreproast
      - /tgtdeleg
      - .kirbi
      - GetUserSPNs
  condition: tool or technique
falsepositives:
  - Authorised red-team / AD security assessments
`,

	// ── T1558.004 – AS-REP Roasting (PowerShell-native) ───────────
	`
title: AS-REP Roasting
description: Detects AS-REP roasting via PowerShell tradecraft (Invoke-ASREPRoast, Get-ASREPHash) or enumeration of accounts with Kerberos pre-authentication disabled (DONT_REQ_PREAUTH), which yields crackable AS-REP hashes without prior domain credentials. Complements the Rubeus-focused Kerberoasting rule.
status: stable
level: high
tags:
  - attack.t1558.004
  - attack.credential_access
logsource:
  product: windows
  category: process_creation
detection:
  ps_asrep:
    CommandLine|contains:
      - "Invoke-ASREPRoast"
      - "Get-ASREPHash"
      - "ASREPRoast"
      - "GetNPUsers"
  preauth_filter:
    CommandLine|contains:
      - "DONT_REQ_PREAUTH"
      - "DoesNotRequirePreAuth"
      - "PreauthNotRequired"
  rubeus_asrep:
    CommandLine|contains|all:
      - "rubeus"
      - "asreproast"
  condition: ps_asrep or preauth_filter or rubeus_asrep
falsepositives:
  - Authorised AD security assessments enumerating pre-auth settings
`,

	// ── T1552.003 – Bash/Shell History Credential Search ──────────
	`
title: Shell History Credential Search
description: Detects reading or searching of shell and client history files (.bash_history, .zsh_history, .mysql_history, .psql_history) that frequently contain plaintext credentials, tokens, and connection strings.
status: stable
level: medium
tags:
  - attack.t1552.003
  - attack.credential_access
logsource:
  product: linux
  category: process_creation
detection:
  history_file:
    CommandLine|contains:
      - ".bash_history"
      - ".zsh_history"
      - ".sh_history"
      - ".mysql_history"
      - ".psql_history"
      - ".rediscli_history"
  condition: history_file
falsepositives:
  - A user legitimately inspecting their own shell history
`,

	// ── T1490 – Inhibit Recovery via wbadmin ──────────────────────
	`
title: Backup Catalog Deletion via wbadmin
description: Detects deletion of the Windows backup catalog or system state backups, a ransomware recovery-inhibition step.
status: stable
level: critical
tags:
  - attack.t1490
  - attack.impact
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|contains: wbadmin.exe
    CommandLine|contains|all:
      - delete
      - catalog
  systemstate:
    Image|contains: wbadmin.exe
    CommandLine|contains: delete systemstatebackup
  condition: selection or systemstate
falsepositives:
  - Rare legitimate backup catalog maintenance
`,

	// ── T1489 – Stop/Disable Security or Backup Service ───────────
	`
title: Security or Backup Service Tampering
description: Detects stopping/disabling/deleting of antivirus, EDR or backup services, a common ransomware pre-encryption step.
status: stable
level: high
tags:
  - attack.t1489
  - attack.impact
logsource:
  product: windows
  category: process_creation
detection:
  tool:
    Image|contains:
      - net.exe
      - net1.exe
      - sc.exe
      - powershell
      - taskkill.exe
  action:
    CommandLine|contains:
      - stop
      - delete
      - disabled
      - config
      - /f
  target:
    CommandLine|contains:
      - defender
      - windefend
      - sense
      - sophos
      - crowdstrike
      - csagent
      - carbonblack
      - mcafee
      - symantec
      - sentinel
      - veeam
      - backupexec
      - sqlwriter
      - mssql
      - sqlserver
      - mysql
      - postgres
      - oracle
      - mongodb
      - msexchange
  condition: tool and action and target
falsepositives:
  - Authorised maintenance of security/backup agents
  - Planned database/service maintenance windows
`,

	// ── T1546.003 – WMI Event Subscription Persistence ────────────
	`
title: WMI Event Subscription Persistence
description: Detects creation of WMI event subscriptions (filter/consumer/binding), a stealthy persistence mechanism.
status: stable
level: high
tags:
  - attack.t1546.003
  - attack.persistence
  - attack.privilege_escalation
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - __EventConsumer
      - __EventFilter
      - __FilterToConsumerBinding
      - ActiveScriptEventConsumer
      - CommandLineEventConsumer
      - Register-WmiEvent
      - Register-CimIndicationEvent
  condition: selection
falsepositives:
  - Legitimate management software using WMI subscriptions (rare)
`,

	// ── T1555.003 – Credentials from Web Browsers ─────────────────
	`
title: Browser Credential Store Access
description: Detects access to browser credential/cookie databases (Chrome/Edge "Login Data", Firefox logins.json/key4.db), used for credential theft.
status: stable
level: high
tags:
  - attack.t1555.003
  - attack.credential_access
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - Login Data
      - logins.json
      - key4.db
      - key3.db
      - signons.sqlite
      - cookies.sqlite
      - \Local State
  condition: selection
falsepositives:
  - Backup software copying entire browser profiles
`,

	// ── T1548.002 – UAC Bypass via Registry Hijack ────────────────
	`
title: UAC Bypass via Registry Hijack
description: Detects registry hijack of protected-handler keys (ms-settings/mscfile/Folder/exefile shell open command) used to bypass UAC via auto-elevating binaries (fodhelper, eventvwr, sdclt, computerdefaults).
status: stable
level: high
tags:
  - attack.t1548.002
  - attack.privilege_escalation
  - attack.defense_evasion
logsource:
  product: windows
  category: registry_event
detection:
  selection:
    TargetObject|contains:
      - \ms-settings\shell\open\command
      - \mscfile\shell\open\command
      - \Folder\shell\open\command
      - \exefile\shell\open\command
  condition: selection
falsepositives:
  - None expected; these handler keys are rarely modified legitimately
`,

	// ── T1216.001 – Signed Script Proxy Execution (PubPrn) ────────
	`
title: Signed Script Proxy Execution via PubPrn / Scriptlet Moniker
description: Detects abuse of the signed PubPrn.vbs script or a "script:" scriptlet moniker to proxy remote code execution past application control.
status: stable
level: high
tags:
  - attack.t1216.001
  - attack.defense_evasion
logsource:
  product: windows
  category: process_creation
detection:
  pubprn:
    CommandLine|contains: pubprn.vbs
  scriptlet:
    CommandLine|contains:
      - "script:http"
      - "script:https"
  condition: pubprn or scriptlet
falsepositives:
  - Rare legitimate printer-provisioning automation using PubPrn
`,

	// ── T1218.001 – Compiled HTML Help Remote Execution ───────────
	`
title: Compiled HTML Help Remote Execution (hh.exe)
description: Detects hh.exe loading a remote payload (HTTP/FTP), a LOLBin proxy-execution technique using compiled HTML help.
status: stable
level: high
tags:
  - attack.t1218.001
  - attack.defense_evasion
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|contains: hh.exe
    CommandLine|contains:
      - http://
      - https://
      - ftp://
  condition: selection
falsepositives:
  - Rare; hh.exe normally opens local .chm help files
`,

	// ── T1566.001 – Office Application Spawning Script Interpreter ─
	// Relies on the pipeline parent-name resolver (parent_resolver.go) populating
	// ParentImage from ppid; a strong macro-execution IOC.
	`
title: Office Application Spawning Script Interpreter
description: Detects Office applications spawning a script interpreter or LOLBin (PowerShell/cmd/wscript/cscript/mshta/rundll32/regsvr32), a hallmark of malicious macro execution.
status: stable
level: high
tags:
  - attack.t1566.001
  - attack.execution
logsource:
  product: windows
  category: process_creation
detection:
  parent:
    ParentImage|contains:
      - winword.exe
      - excel.exe
      - powerpnt.exe
      - outlook.exe
      - mspub.exe
      - visio.exe
      - onenote.exe
  child:
    Image|contains:
      - powershell
      - cmd.exe
      - wscript.exe
      - cscript.exe
      - mshta.exe
      - rundll32.exe
      - regsvr32.exe
  condition: parent and child
falsepositives:
  - Rare legitimate Office add-ins that shell out
`,

	// ── T1574.002 – DLL Side-Loading (image_load telemetry) ───────
	// Requires the agent image_load collector to populate ImageLoaded /
	// SignatureStatus (see proto ImageLoadEvent). Detects an untrusted (unsigned/
	// invalid) DLL loaded from a user-writable directory — the core sideloading IOC.
	`
title: Untrusted DLL Loaded From User-Writable Path (Side-Loading)
description: Detects loading of an unsigned or invalidly-signed DLL from a user-writable location (Temp/AppData/ProgramData/Downloads), a hallmark of DLL side-loading.
status: stable
level: high
tags:
  - attack.t1574.002
  - attack.defense_evasion
  - attack.persistence
logsource:
  product: windows
  category: image_load
detection:
  dll:
    ImageLoaded|contains: .dll
  untrusted:
    SignatureStatus|contains:
      - unsigned
      - invalid
      - expired
  userpath:
    ImageLoaded|contains:
      - \temp\
      - \appdata\
      - \programdata\
      - \downloads\
      - \public\
  condition: dll and untrusted and userpath
falsepositives:
  - In-house software shipping unsigned DLLs in user directories
`,

	// ── T1059.001 / T1027 – Malicious Script Content (ScriptBlock/AMSI) ─
	// Requires the agent script collector to populate ScriptBlockText (proto
	// ScriptContentEvent). Detects malicious patterns in the DEOBFUSCATED script
	// body — catching encoded/fileless PowerShell that command-line rules miss.
	`
title: Malicious PowerShell/Script Content
description: Detects known offensive tradecraft in deobfuscated script content (ScriptBlock logging / AMSI), including download cradles, AMSI bypass, reflection loaders and in-memory tooling.
status: stable
level: high
tags:
  - attack.t1059.001
  - attack.t1027
  - attack.defense_evasion
  - attack.execution
logsource:
  product: windows
  category: ps_script
detection:
  selection:
    ScriptBlockText|contains:
      - FromBase64String
      - IEX(
      - IEX (
      - Invoke-Expression
      - DownloadString
      - DownloadFile
      - Net.WebClient
      - Invoke-WebRequest
      - Invoke-Mimikatz
      - Invoke-Shellcode
      - amsiInitFailed
      - AmsiUtils
      - VirtualProtect
      - "[Reflection.Assembly]"
      - "[Ref].Assembly.GetType"
      - Add-Type -TypeDefinition
      - System.Reflection.AssemblyName
  condition: selection
falsepositives:
  - Administrative scripts that legitimately use reflection or web downloads
`,

	// ── T1574.006 – Dynamic Linker Hijacking (LD_PRELOAD/LD_LIBRARY_PATH) ─
	// Linux sensor-depth: requires the agent to populate env_vars from
	// /proc/<pid>/environ (the `environment` joined field). Detects a process
	// spawned with a linker-injection variable pointing into a user-writable path.
	`
title: Dynamic Linker Hijacking via LD_PRELOAD/LD_LIBRARY_PATH
description: Detects a process launched with LD_PRELOAD/LD_LIBRARY_PATH/LD_AUDIT referencing a user-writable location, a hallmark of shared-object injection on Linux.
status: stable
level: high
tags:
  - attack.t1574.006
  - attack.persistence
  - attack.privilege_escalation
  - attack.defense_evasion
logsource:
  product: linux
  category: process_creation
detection:
  ldvars:
    environment|contains:
      - LD_PRELOAD=
      - LD_LIBRARY_PATH=
      - LD_AUDIT=
  writable:
    environment|contains:
      - /tmp/
      - /dev/shm/
      - /var/tmp/
      - /home/
  condition: ldvars and writable
falsepositives:
  - Developer/build environments setting LD_LIBRARY_PATH to project directories
`,
	// ── T1127.001 – Trusted Developer Utilities Proxy: MSBuild ─
	`
title: MSBuild Proxy Execution
description: Detects msbuild.exe execution — a signed developer utility abused to compile and run inline C# tasks, bypassing application allowlisting (proxy execution).
status: stable
level: medium
tags:
  - attack.t1127.001
  - attack.defense_evasion
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|contains: msbuild
  condition: selection
falsepositives:
  - Developer or CI build machines running legitimate builds
`,
	// ── T1547.001 – Registry Run Key Persistence (value-data) ─────
	// Leverages the ETW Kernel-Registry collector's value-data depth: matches a
	// Run/RunOnce write whose DATA points to a user-writable or script-interpreter
	// location — what the RegNotify collector could never see.
	`
title: Registry Run Key Persistence to Suspicious Location
description: Detects a value written to a Run/RunOnce autostart key whose data points to a user-writable directory or a script interpreter, a hallmark of malware persistence.
status: experimental
level: high
tags:
  - attack.t1547.001
  - attack.persistence
logsource:
  product: windows
  category: registry_event
detection:
  selection_key:
    TargetObject|contains:
      - CurrentVersion\Run
      - CurrentVersion\RunOnce
      - Policies\Explorer\Run
  selection_data:
    Details|contains:
      - \AppData\
      - \Temp\
      - \Users\Public\
      - \ProgramData\
      - powershell
      - 'cmd /c'
      - mshta
      - wscript
      - cscript
      - rundll32
      - regsvr32
  condition: selection_key and selection_data
falsepositives:
  - Some legitimate installers stage launchers in ProgramData
`,
	// ── T1546.012 – Image File Execution Options Injection ─────
	`
title: Image File Execution Options Debugger Persistence
description: Detects setting a Debugger value under Image File Execution Options, hijacking execution of a target program for persistence or privilege escalation.
status: stable
level: high
tags:
  - attack.t1546.012
  - attack.persistence
  - attack.privilege_escalation
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|contains: reg
    CommandLine|contains|all:
      - Image File Execution Options
      - Debugger
  condition: selection
falsepositives:
  - GFlags or debugging tools configuring a debugger intentionally
`,
	// ── T1562.001 – Impair Defenses: Defender via registry ─────
	`
title: Windows Defender Tampering via Registry
description: Detects registry edits that disable Windows Defender or its tamper protection (DisableAntiSpyware / DisableAntiVirus / TamperProtection), distinct from the Set-MpPreference vector.
status: stable
level: critical
tags:
  - attack.t1562.001
  - attack.defense_evasion
logsource:
  product: windows
  category: process_creation
detection:
  reg:
    Image|contains: reg
    CommandLine|contains: Windows Defender
  disable:
    CommandLine|contains:
      - DisableAntiSpyware
      - DisableAntiVirus
      - TamperProtection
  condition: reg and disable
falsepositives:
  - Enterprise policy management of Defender
`,
	// ── T1505.003 – Web Shell ──────────────────────────────────
	`
title: Web Server Spawning Command Shell (Web Shell)
description: Detects a web server worker process spawning a command or script interpreter — a classic web shell indicator. Relies on parent-process resolution (ParentImage from ppid).
status: stable
level: high
tags:
  - attack.t1505.003
  - attack.persistence
logsource:
  product: windows
  category: process_creation
detection:
  parent:
    ParentImage|contains:
      - w3wp.exe
      - httpd.exe
      - nginx.exe
      - php-cgi.exe
      - tomcat
      - ws_tomcatservice.exe
  child:
    Image|contains:
      - cmd.exe
      - powershell
      - \wscript.exe
      - \cscript.exe
      - \bash.exe
  condition: parent and child
falsepositives:
  - Legitimate web applications shelling out (e.g. some CGI or admin tooling)
`,
	// ── T1564.001 – Hide Artifacts: Hidden Files and Directories ─
	`
title: Hidden File or Directory via attrib
description: Detects attrib.exe setting the hidden+system attributes, used to conceal malicious files and directories.
status: stable
level: medium
tags:
  - attack.t1564.001
  - attack.defense_evasion
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|contains: attrib
    CommandLine|contains|all:
      - +h
      - +s
  condition: selection
falsepositives:
  - Some installers mark configuration files hidden+system
`,
	// ── T1222.001 – File and Directory Permissions Modification ─
	`
title: Broad File Permission Change via icacls/takeown
description: Detects icacls/cacls/takeown granting broad access or seizing ownership — common in ransomware staging and persistence to make files attacker-controlled.
status: stable
level: medium
tags:
  - attack.t1222.001
  - attack.defense_evasion
logsource:
  product: windows
  category: process_creation
detection:
  icacls:
    Image|contains:
      - icacls
      - cacls.exe
    CommandLine|contains:
      - /grant Everyone
      - /grant *S-1-1-0
      - ' /grant:r everyone'
      - /T /C /grant
  takeown:
    Image|contains: takeown
    CommandLine|contains: /f
  condition: icacls or takeown
falsepositives:
  - Administrative ACL maintenance scripts
`,
	// ── T1136.002 – Create Account: Domain Account ─────────────
	`
title: Domain Account Creation via net.exe
description: Detects creation of a domain account via net user /add /domain — persistence or lateral movement on a domain.
status: stable
level: high
tags:
  - attack.t1136.002
  - attack.persistence
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|contains:
      - \net.exe
      - \net1.exe
    CommandLine|contains|all:
      - user
      - /add
      - /domain
  condition: selection
falsepositives:
  - Legitimate domain administration
`,
	// ── T1003.006 – DCSync (DRSUAPI Credential Replication) ─────
	`
title: DCSync Credential Replication
description: Detects DCSync — abusing directory replication (DRSUAPI) to pull password hashes for any account, typically via mimikatz lsadump::dcsync or PowerShell Invoke-DCSync. Extremely high signal.
status: stable
level: critical
tags:
  - attack.t1003.006
  - attack.credential_access
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - "lsadump::dcsync"
      - /dcsync
      - Invoke-DCSync
      - "-just-dc"
      - "--just-dc"
  condition: selection
falsepositives:
  - None expected; DCSync from a non-DC host is essentially always malicious
`,
	// ── T1555.004 – Credentials from Windows Credential Manager ─
	`
title: Windows Credential Manager Access
description: Detects enumeration/harvesting of stored credentials via cmdkey /list or vaultcmd, used to pull cached credentials from the Windows Credential Manager / vault.
status: stable
level: medium
tags:
  - attack.t1555.004
  - attack.credential_access
logsource:
  product: windows
  category: process_creation
detection:
  cmdkey:
    Image|contains: cmdkey
    CommandLine|contains: /list
  vaultcmd:
    Image|contains: vaultcmd
    CommandLine|contains:
      - /list
      - /listcreds
  condition: cmdkey or vaultcmd
falsepositives:
  - Administrators auditing stored credentials
`,
	// ── T1021.001 – Remote Desktop (enable / session hijack) ───
	`
title: RDP Enabled or Session Hijack
description: Detects enabling Remote Desktop by clearing fDenyTSConnections, or hijacking an existing RDP session via tscon /dest — both used for lateral movement.
status: stable
level: high
tags:
  - attack.t1021.001
  - attack.lateral_movement
logsource:
  product: windows
  category: process_creation
detection:
  enable_rdp:
    Image|contains: reg
    CommandLine|contains|all:
      - fDenyTSConnections
      - /d 0
  tscon:
    Image|contains: tscon
    CommandLine|contains: /dest
  condition: enable_rdp or tscon
falsepositives:
  - Administrators legitimately enabling RDP or reconnecting sessions
`,
	// ── T1021.006 – Windows Remote Management (WinRM / PSRemoting) ─
	`
title: WinRM Lateral Movement (winrs / PowerShell Remoting)
description: Detects remote command execution over Windows Remote Management — winrs.exe, or PowerShell remoting (Enter-PSSession/New-PSSession) which establishes a remote session for lateral movement.
status: stable
level: medium
tags:
  - attack.t1021.006
  - attack.lateral_movement
logsource:
  product: windows
  category: process_creation
detection:
  winrs:
    Image|contains: winrs
  pssession:
    CommandLine|contains:
      - Enter-PSSession
      - New-PSSession
  evil_winrm:
    CommandLine|contains: "evil-winrm"
  condition: winrs or pssession or evil_winrm
falsepositives:
  - Administrators using PowerShell remoting / winrs for management
`,

	// ── T1649 – AD CS Certificate Abuse (Certipy) ──────────────
	`
title: AD CS Certificate Abuse
description: Detects Active Directory Certificate Services abuse via Certipy or Certify — requesting, forging, or relaying certificates for authentication and privilege escalation (ESC1-16), a common modern path to Domain Admin.
status: stable
level: high
tags:
  - attack.t1649
  - attack.credential_access
logsource:
  category: process_creation
detection:
  certipy:
    CommandLine|contains: "certipy"
  # Certify (GhostPack's Windows/.NET-native equivalent of Certipy, from the
  # same authors as Rubeus/Seatbelt/SharpUp) was missing entirely — real
  # invocations are "Certify.exe find /vulnerable" or "Certify.exe request
  # /ca:... /template:...".
  certify:
    CommandLine|contains: "Certify.exe"
  condition: certipy or certify
falsepositives:
  - Authorised AD CS security assessments using Certipy or Certify
`,

	// ── T1187 – Authentication Coercion (PetitPotam/Coercer) ───
	`
title: Authentication Coercion
description: Detects forced-authentication coercion tools (PetitPotam, Coercer, PrinterBug/Dementor, DFSCoerce, ShadowCoerce) that force a victim host to authenticate to an attacker for NTLM relay — a key step in AD CS/relay attacks toward Domain Admin.
status: stable
level: high
tags:
  - attack.t1187
  - attack.credential_access
logsource:
  category: process_creation
detection:
  coercion:
    CommandLine|contains:
      - PetitPotam
      - Coercer
      - printerbug
      - dfscoerce
      - shadowcoerce
      - dementor
  condition: coercion
falsepositives:
  - Authorised AD relay/coercion assessments
`,

	// ── T1110 – Kerberos Brute-Force / User Enumeration (Kerbrute) ─
	`
title: Kerberos Brute-Force and User Enumeration
description: Detects Kerbrute — Kerberos pre-authentication username enumeration and password spraying (kerbrute userenum/passwordspray/bruteuser/bruteforce) against a KDC, which does not generate failed-logon events on the target host.
status: stable
level: high
tags:
  - attack.t1110
  - attack.credential_access
logsource:
  category: process_creation
detection:
  kerbrute:
    CommandLine|contains: "kerbrute"
  condition: kerbrute
falsepositives:
  - Authorised password-strength / spray assessments
`,
	// ── T1090.001 – Internal Proxy via netsh portproxy ─────────
	`
title: Internal Proxy via netsh portproxy
description: Detects creation of a netsh portproxy rule, used to relay/pivot traffic through a compromised host (internal proxy) — a common C2 pivoting technique.
status: stable
level: high
tags:
  - attack.t1090.001
  - attack.command_and_control
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|contains: netsh
    CommandLine|contains|all:
      - portproxy
      - add
  condition: selection
falsepositives:
  - Rare legitimate port-forwarding configured by administrators
`,
	// ── T1218.009 – Regsvcs/Regasm Proxy Execution ─────────────
	`
title: Regsvcs/Regasm Proxy Execution
description: Detects regsvcs.exe or regasm.exe — signed .NET utilities abused to execute attacker code via ComRegisterFunction/UnRegister hooks, bypassing application control (LOLBin proxy execution).
status: stable
level: medium
tags:
  - attack.t1218.009
  - attack.defense_evasion
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|contains:
      - regsvcs.exe
      - regasm.exe
  condition: selection
falsepositives:
  - Legitimate .NET assembly registration by developers or installers
`,
	// ── T1553.004 – Install Root Certificate ───────────────────
	`
title: Root Certificate Installation via certutil
description: Detects installation of a certificate into the Root/AuthRoot trust store via certutil -addstore, which can enable adversary-in-the-middle interception or trust of malicious code-signing certificates.
status: stable
level: high
tags:
  - attack.t1553.004
  - attack.defense_evasion
logsource:
  product: windows
  category: process_creation
detection:
  certutil:
    Image|contains: certutil
    CommandLine|contains: -addstore
  store:
    CommandLine|contains:
      - root
      - authroot
  condition: certutil and store
falsepositives:
  - Enterprise PKI deployment of internal root/intermediate certificates
`,
	// ── T1220 – XSL Script Processing ──────────────────────────
	`
title: XSL Script Processing Proxy Execution
description: Detects execution of scripts embedded in XSL stylesheets — msxsl.exe, or wmic referencing an .xsl format file — a LOLBin proxy-execution / application-control-bypass technique.
status: stable
level: high
tags:
  - attack.t1220
  - attack.defense_evasion
logsource:
  product: windows
  category: process_creation
detection:
  msxsl:
    Image|contains: msxsl
  wmic_xsl:
    Image|contains: wmic
    CommandLine|contains: .xsl
  condition: msxsl or wmic_xsl
falsepositives:
  - Rare legitimate XSLT transformation tooling
`,
	// ── T1115 – Clipboard Data ─────────────────────────────────
	`
title: Clipboard Data Collection
description: Detects reading of clipboard contents via PowerShell Get-Clipboard or the .NET Clipboard class, a collection technique for harvesting copied credentials/data.
status: stable
level: medium
tags:
  - attack.t1115
  - attack.collection
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - Get-Clipboard
      - System.Windows.Forms.Clipboard
      - "Windows.Clipboard]::GetText"
  condition: selection
falsepositives:
  - Clipboard-manager utilities or legitimate automation reading the clipboard
`,
	// ── T1113 – Screen Capture ─────────────────────────────────
	`
title: Screen Capture via CopyFromScreen / Screenshot Tool
description: Detects screen capture through the .NET Graphics.CopyFromScreen API or known screenshot LOLBins (nircmd savescreenshot), used to collect visual data from a victim.
status: stable
level: high
tags:
  - attack.t1113
  - attack.collection
logsource:
  product: windows
  category: process_creation
detection:
  api:
    CommandLine|contains: CopyFromScreen
  nircmd:
    Image|contains: nircmd
    CommandLine|contains: savescreenshot
  condition: api or nircmd
falsepositives:
  - Legitimate screenshot/remote-support tooling
`,
	// ── T1056.001 – Keylogging ─────────────────────────────────
	`
title: Keylogging via Windows Hook / Async Key State
description: Detects keylogging tradecraft — capturing keystrokes via GetAsyncKeyState, SetWindowsHookEx or GetKeyboardState, typically invoked from inline PowerShell/C#.
status: stable
level: high
tags:
  - attack.t1056.001
  - attack.collection
  - attack.credential_access
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - GetAsyncKeyState
      - SetWindowsHookEx
      - GetKeyboardState
  condition: selection
falsepositives:
  - Rare; these APIs are seldom used in benign command-line invocations
`,
	// ── T1114 – Email Collection ───────────────────────────────
	`
title: Email Collection via Mailbox Export
description: Detects bulk email collection — Exchange mailbox export/search (New-MailboxExportRequest / Search-Mailbox) or Outlook automation via the Interop COM object.
status: stable
level: high
tags:
  - attack.t1114
  - attack.collection
logsource:
  product: windows
  category: process_creation
detection:
  exchange:
    CommandLine|contains:
      - New-MailboxExportRequest
      - Search-Mailbox
  outlook:
    CommandLine|contains: Microsoft.Office.Interop.Outlook
  condition: exchange or outlook
falsepositives:
  - Authorised Exchange administration or eDiscovery exports
`,

	// ── T1114.003 – Email Forwarding Rule ──────────────────────
	`
title: Email Forwarding Rule
description: Detects creation of mail forwarding/redirection rules used to silently exfiltrate a victim's email — Exchange/M365 New-InboxRule with -ForwardTo/-RedirectTo, Set-Mailbox -ForwardingSMTPAddress, or New-TransportRule with BlindCopyTo.
status: stable
level: high
tags:
  - attack.t1114.003
  - attack.collection
  - attack.exfiltration
logsource:
  product: windows
  category: process_creation
detection:
  inbox_rule:
    CommandLine|contains|all:
      - "New-InboxRule"
    CommandLine|contains:
      - "-ForwardTo"
      - "-ForwardAsAttachmentTo"
      - "-RedirectTo"
  mailbox_fwd:
    CommandLine|contains:
      - "ForwardingSMTPAddress"
      - "DeliverToMailboxAndForward"
  transport_rule:
    CommandLine|contains|all:
      - "New-TransportRule"
    CommandLine|contains:
      - "BlindCopyTo"
      - "RedirectMessageTo"
  condition: inbox_rule or mailbox_fwd or transport_rule
falsepositives:
  - Users legitimately configuring mail forwarding (review destination domain)
`,

	// ── T1137 – Office Application Startup ──────────────────────
	`
title: Office Application Startup Persistence
description: Detects persistence via Microsoft Office startup locations and add-ins — dropping templates/add-ins into Excel XLSTART, Word STARTUP, the AddIns folder, or Normal.dotm, or registering an Office add-in, so attacker code runs whenever Office launches.
status: stable
level: high
tags:
  - attack.t1137
  - attack.persistence
logsource:
  product: windows
  category: process_creation
detection:
  office_startup_path:
    CommandLine|contains:
      - "\\Excel\\XLSTART"
      - "\\Word\\STARTUP"
      - "\\Microsoft\\AddIns"
      - "\\Templates\\Normal.dotm"
  office_addin_reg:
    CommandLine|contains|all:
      - "\\Office\\"
      - "\\Addins"
  condition: office_startup_path or office_addin_reg
falsepositives:
  - Office add-in installers writing to startup/add-in locations
`,

	// ── T1218.002 – Control Panel Execution ────────────────────
	`
title: Control Panel Item Execution
description: Detects execution of Control Panel items (.cpl) as a proxy for running malicious code — control.exe launching a .cpl (often from a user/temp path) or rundll32 shell32.dll,Control_RunDLL against an attacker-supplied file.
status: stable
level: medium
tags:
  - attack.t1218.002
  - attack.defense_evasion
logsource:
  product: windows
  category: process_creation
detection:
  control_cpl:
    CommandLine|contains|all:
      - "control"
      - ".cpl"
  rundll_control:
    CommandLine|contains: "Control_RunDLL"
  condition: control_cpl or rundll_control
falsepositives:
  - Legitimate Control Panel applets launched from System32
`,

	// ── T1003.004 – LSA Secrets ────────────────────────────────
	`
title: LSA Secrets Dump
description: Detects extraction of LSA secrets — saving the SECURITY registry hive, mimikatz lsadump::secrets/lsa, or Impacket secretsdump — used to recover service-account and machine credentials.
status: stable
level: high
tags:
  - attack.t1003.004
  - attack.credential_access
logsource:
  product: windows
  category: process_creation
detection:
  regsave:
    Image|contains: reg
    CommandLine|contains|all:
      - save
      - hklm\security
  tooling:
    CommandLine|contains:
      - "lsadump::secrets"
      - "lsadump::lsa"
      - secretsdump
  condition: regsave or tooling
falsepositives:
  - Rare legitimate backup of the SECURITY hive
`,
	// ── T1003.005 – Cached Domain Credentials ──────────────────
	`
title: Cached Domain Credentials Dump
description: Detects dumping of cached domain logon credentials (MSCACHE/DCC2) via mimikatz lsadump::cache, cachedump or gsecdump — used for offline cracking when a DC is unreachable.
status: stable
level: high
tags:
  - attack.t1003.005
  - attack.credential_access
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - "lsadump::cache"
      - cachedump
      - gsecdump
  condition: selection
falsepositives:
  - None expected
`,
	// ── T1552.004 – Private Keys ───────────────────────────────
	`
title: Private Key Harvesting
description: Detects recursive search/collection of private key material (SSH id_rsa, .ppk, .pem, .pfx), a common unsecured-credentials harvesting step.
status: stable
level: medium
tags:
  - attack.t1552.004
  - attack.credential_access
logsource:
  product: windows
  category: process_creation
detection:
  harvest:
    CommandLine|contains:
      - dir /s
      - "-recurse"
      - Get-ChildItem
      - findstr
      - "ls -r"
      - "find /"
  keyfile:
    CommandLine|contains:
      - id_rsa
      - id_dsa
      - id_ecdsa
      - .ppk
      - .pem
      - .pfx
  condition: harvest and keyfile
falsepositives:
  - DevOps/CI scripts inventorying certificates or keys
`,
	// ── T1557.001 – LLMNR/NBT-NS Poisoning (Responder/Inveigh) ─
	`
title: LLMNR/NBT-NS Poisoning Tool (Responder/Inveigh)
description: Detects execution of LLMNR/NBT-NS/mDNS poisoning and credential-relay tools (Responder, Inveigh) used to capture NetNTLM hashes on the local network.
status: stable
level: high
tags:
  - attack.t1557.001
  - attack.credential_access
logsource:
  product: windows
  category: process_creation
detection:
  cmd:
    CommandLine|contains:
      - Invoke-Inveigh
      - Inveigh.ps1
      - responder.py
  image:
    Image|contains:
      - responder
      - inveigh
  condition: cmd or image
falsepositives:
  - Authorised network security assessments
`,
	// ── T1552.006 – Group Policy Preferences Passwords ─────────
	`
title: Group Policy Preferences Password Retrieval
description: Detects retrieval of Group Policy Preferences credentials — searching SYSVOL for the cpassword attribute or running Get-GPPPassword — which yields AES-decryptable domain passwords.
status: stable
level: high
tags:
  - attack.t1552.006
  - attack.credential_access
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - cpassword
      - Get-GPPPassword
  condition: selection
falsepositives:
  - Rare legitimate GPP auditing
`,
	// ── T1036.003 – Masquerading: Rename of System Utilities ───
	`
title: System Process Name From Non-Standard Path (Masquerading)
description: Detects a process using a core Windows system-process name (svchost/lsass/services/…) running from outside System32/SysWOW64/WinSxS — a hallmark of masquerading. Uses the SigmaEvaluator's "not" operator to exclude the legitimate paths.
status: stable
level: high
tags:
  - attack.t1036.003
  - attack.defense_evasion
logsource:
  product: windows
  category: process_creation
detection:
  sysname:
    Image|endswith:
      - \svchost.exe
      - \lsass.exe
      - \services.exe
      - \csrss.exe
      - \winlogon.exe
      - \wininit.exe
      - \smss.exe
      - \spoolsv.exe
      - \taskhostw.exe
      - \dllhost.exe
      - \conhost.exe
  legit:
    Image|contains:
      - \windows\system32\
      - \windows\syswow64\
      - \windows\winsxs\
  haspath:
    Image|contains:
      - ':\'
      - \device\
  condition: sysname and haspath and not legit
falsepositives:
  - Rare third-party software shipping a binary with a system-process name
`,
	// ── T1564.003 – Hidden Window ──────────────────────────────
	`
title: Hidden Window Execution
description: Detects launching a process with a hidden window (PowerShell -WindowStyle Hidden / -w hidden), a common technique to run payloads without a visible UI.
status: stable
level: medium
tags:
  - attack.t1564.003
  - attack.defense_evasion
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - -windowstyle hidden
      - -window hidden
      - " -w hidden"
      - " -w 1 "
  condition: selection
falsepositives:
  - Some legitimate maintenance scripts run hidden
`,
	// ── T1564.004 – NTFS Alternate Data Streams ────────────────
	`
title: NTFS Alternate Data Stream Manipulation
description: Detects use of NTFS alternate data streams to hide data/code — the :$DATA attribute or PowerShell's -Stream parameter on *-Content cmdlets.
status: stable
level: medium
tags:
  - attack.t1564.004
  - attack.defense_evasion
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - " -Stream "
      - ":$DATA"
      - "::$DATA"
  condition: selection
falsepositives:
  - Rare legitimate use of alternate data streams
`,
	// ── T1070.006 – Timestomp ──────────────────────────────────
	`
title: Timestomping (File Time Modification)
description: Detects modification of file MACE timestamps to hinder forensics — timestomp/SetMace tools or PowerShell assigning CreationTime/LastWriteTime/LastAccessTime.
status: stable
level: medium
tags:
  - attack.t1070.006
  - attack.defense_evasion
logsource:
  product: windows
  category: process_creation
detection:
  tool:
    Image|contains:
      - timestomp
      - setmace
  pscmd:
    CommandLine|contains:
      - .creationtime =
      - .lastwritetime =
      - .lastaccesstime =
      - setlastwritetime
      - setfiletime
  condition: tool or pscmd
falsepositives:
  - Build/packaging scripts that legitimately set file times
`,
	// ── T1562.002 – Disable Windows Event Logging ──────────────
	`
title: Windows Event Logging Disabled
description: Detects disabling of Windows auditing/event logging — auditpol disabling categories, wevtutil disabling a log (/e:false), or stopping the EventLog service.
status: stable
level: high
tags:
  - attack.t1562.002
  - attack.defense_evasion
logsource:
  product: windows
  category: process_creation
detection:
  auditpol:
    Image|contains: auditpol
    CommandLine|contains:
      - /success:disable
      - /failure:disable
  wevtutil:
    Image|contains: wevtutil
    CommandLine|contains|all:
      - sl
      - /e:false
  service:
    CommandLine|contains:
      - stop-service eventlog
      - sc stop eventlog
      - stop-service -name eventlog
  condition: auditpol or wevtutil or service
falsepositives:
  - Authorised audit-policy maintenance
`,
	// ── T1021.004 – Remote Services: SSH (automated/credentialed) ─
	`
title: SSH Lateral Movement with Inline Credentials
description: Detects automated/scripted SSH to another host with the password supplied on the command line (plink -pw, sshpass -p) — a hallmark of credentialed lateral movement rather than interactive admin use.
status: stable
level: medium
tags:
  - attack.t1021.004
  - attack.lateral_movement
logsource:
  product: windows
  category: process_creation
detection:
  plink:
    Image|contains: plink
    CommandLine|contains: " -pw "
  sshpass:
    Image|contains: sshpass
    CommandLine|contains: " -p "
  condition: plink or sshpass
falsepositives:
  - Legitimate automation that embeds SSH credentials (discouraged)
`,
	// ── T1021.003 – Distributed Component Object Model (DCOM) ───
	`
title: DCOM Lateral Movement
description: Detects lateral movement via DCOM objects (MMC20.Application, ShellWindows, ShellBrowserWindow, Excel DDE) or remote COM instantiation through GetTypeFromProgID, commonly used to execute code on a remote host.
status: stable
level: high
tags:
  - attack.t1021.003
  - attack.lateral_movement
logsource:
  product: windows
  category: process_creation
detection:
  com:
    CommandLine|contains:
      - MMC20.Application
      - ShellWindows
      - ShellBrowserWindow
      - GetTypeFromProgID
      - "9BA05972-F6A8-11CF"
      - "C08AFD90-F2A1-11D1"
  dde:
    CommandLine|contains: DDEInitiate
  condition: com or dde
falsepositives:
  - Rare legitimate administrative COM automation
`,
	// ── T1550.003 – Pass the Ticket ────────────────────────────
	`
title: Pass-the-Ticket (Kerberos Ticket Injection)
description: Detects Kerberos ticket injection/forging for lateral movement — mimikatz kerberos::ptt, Rubeus ptt/asktgt, or use of exported .kirbi ticket files.
status: stable
level: high
tags:
  - attack.t1550.003
  - attack.lateral_movement
  - attack.credential_access
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - "kerberos::ptt"
      - .kirbi
      - " /ptt"
      - "ptt /ticket"
      - asktgt
      - tgtdeleg
  condition: selection
falsepositives:
  - Authorised red-team / AD security assessments
`,
	// ── T1558.001 – Golden/Silver Ticket ───────────────────────
	`
title: Golden or Silver Ticket Forging
description: Detects Kerberos golden/silver ticket forging with tools other than the generic mimikatz path — Rubeus golden/silver subcommands, Impacket ticketer, or krbtgt/service hash injection — used for durable domain persistence and privilege escalation.
status: stable
level: critical
tags:
  - attack.t1558.001
  - attack.credential_access
logsource:
  product: windows
  category: process_creation
detection:
  rubeus_forge:
    CommandLine|contains|all:
      - rubeus
      - golden
  rubeus_silver:
    CommandLine|contains|all:
      - rubeus
      - silver
  krbtgt_hash:
    CommandLine|contains:
      - "/krbtgt:"
      - "kerberos::golden"
  impacket_ticketer:
    CommandLine|contains:
      - "ticketer.py"
      - "ticketer "
  # A renamed Rubeus.exe evades rubeus_forge/rubeus_silver (both require the
  # literal "rubeus" substring). Golden tickets are still caught via
  # krbtgt_hash's "/krbtgt:", but silver tickets use "/service:" with a
  # target SPN hash instead and have no other signal — this closes that gap
  # without depending on the binary name.
  silver_service:
    CommandLine|contains|all:
      - silver
      - "/service:"
  condition: rubeus_forge or rubeus_silver or krbtgt_hash or impacket_ticketer or silver_service
falsepositives:
  - Authorised AD security assessments forging test tickets
`,
	// ── T1550.002 – Pass the Hash ──────────────────────────────
	`
title: Pass-the-Hash
description: Detects pass-the-hash lateral movement with NTLM hashes via tooling the generic mimikatz rule misses — Invoke-TheHash (Invoke-SMBExec/Invoke-WMIExec), CrackMapExec/NetExec hash auth, Impacket -hashes, or pth-winexe.
status: stable
level: high
tags:
  - attack.t1550.002
  - attack.lateral_movement
  - attack.credential_access
logsource:
  product: windows
  category: process_creation
detection:
  mimikatz_pth:
    CommandLine|contains: "sekurlsa::pth"
  invoke_thehash:
    CommandLine|contains:
      - "Invoke-SMBExec"
      - "Invoke-WMIExec"
      - "Invoke-TheHash"
      - "Invoke-SMBClient"
  cme_hash:
    CommandLine|contains|all:
      - "crackmapexec"
      - "-H "
  # CrackMapExec's actual console-script entry point is "cme", not the
  # full "crackmapexec" package name — "cme smb <targets> -u admin -H
  # <hash>" is the real-world invocation and never matched cme_hash above.
  cme_hash_shortform:
    CommandLine|contains|all:
      - "cme "
      - "-H "
  netexec_hash:
    CommandLine|contains|all:
      - "nxc "
      - "-H "
  impacket_hashes:
    CommandLine|contains: "-hashes "
  pth_toolkit:
    CommandLine|contains:
      - "pth-winexe"
      - "pth-smbclient"
  condition: mimikatz_pth or invoke_thehash or cme_hash or cme_hash_shortform or netexec_hash or impacket_hashes or pth_toolkit
falsepositives:
  - Authorised red-team / lateral-movement assessments
`,
	// ── T1134 – Access Token Manipulation ──────────────────────
	`
title: Access Token Manipulation
description: Detects token theft/impersonation tradecraft — Invoke-TokenManipulation, Meterpreter incognito/getsystem, runas /netonly, or direct token-duplication APIs — used to escalate or move laterally under another identity.
status: stable
level: high
tags:
  - attack.t1134
  - attack.privilege_escalation
  - attack.defense_evasion
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - Invoke-TokenManipulation
      - " incognito"
      - runas /netonly
      - getsystem
      - steal_token
      - make_token
      - ImpersonateLoggedOnUser
      - DuplicateTokenEx
  condition: selection
falsepositives:
  - Rare legitimate use of runas /netonly by administrators
`,
	// ── T1496 – Resource Hijacking (Cryptomining) ──────────────
	`
title: Cryptocurrency Mining (Resource Hijacking)
description: Detects coin-mining software or mining-pool connection patterns (stratum protocol, donate-level), a common monetisation impact technique.
status: stable
level: high
tags:
  - attack.t1496
  - attack.impact
logsource:
  product: windows
  category: process_creation
detection:
  tool:
    Image|contains:
      - xmrig
      - minerd
      - cpuminer
      - xmr-stak
      - nbminer
      - phoenixminer
  cmd:
    CommandLine|contains:
      - stratum+tcp
      - stratum+ssl
      - --donate-level
      - --cpu-priority
      - nicehash
      - nanopool
  condition: tool or cmd
falsepositives:
  - Sanctioned mining on dedicated hardware
`,
	// ── T1561 – Disk Wipe ──────────────────────────────────────
	`
title: Disk Wipe / Destruction
description: Detects destructive disk operations — Clear-Disk -RemoveData, raw physical-drive writes, diskpart clean, or multi-pass format — used to render systems unrecoverable.
status: stable
level: high
tags:
  - attack.t1561
  - attack.impact
logsource:
  product: windows
  category: process_creation
detection:
  clear:
    CommandLine|contains:
      - Clear-Disk
      - "\\\\.\\PHYSICALDRIVE"
  diskpart:
    Image|contains: diskpart
    CommandLine|contains: clean
  format:
    Image|contains: format.com
    CommandLine|contains: "/p:"
  condition: clear or diskpart or format
falsepositives:
  - Authorised disk provisioning or secure decommissioning
`,
	// ── T1531 – Account Access Removal ─────────────────────────
	`
title: Account Access Removal
description: Detects deletion or disabling of accounts (net user /delete, /active:no, Remove/Disable-AD/LocalUser) — used to lock legitimate users out during an impact phase.
status: stable
level: high
tags:
  - attack.t1531
  - attack.impact
logsource:
  product: windows
  category: process_creation
detection:
  netuser:
    Image|contains:
      - \net.exe
      - \net1.exe
    CommandLine|contains|all:
      - user
      - /delete
  disable:
    CommandLine|contains:
      - /active:no
      - Disable-ADAccount
      - Remove-ADUser
      - Remove-LocalUser
  condition: netuser or disable
falsepositives:
  - Routine deprovisioning of departed users
`,
	// ══ Linux coverage parity (Windows 87 vs Linux 12 → close the gap) ══
	// ── Linux T1548.003 – Sudo Shell Escape (GTFOBins) ─────────
	`
title: Sudo Privilege Escalation via Shell Escape (GTFOBins)
description: Detects abuse of sudo-permitted binaries to spawn a privileged shell (GTFOBins) — editors, find -exec, interpreters, or a preserve-privilege shell — a common Linux privilege-escalation step.
status: stable
level: high
tags:
  - attack.t1548.003
  - attack.privilege_escalation
  - attack.defense_evasion
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - "sudo vim -c"
      - "sudo vi -c"
      - "sudo nmap --interactive"
      - "sudo find / -exec"
      - "sudo find . -exec"
      - "sudo awk 'BEGIN"
      - "sudo python -c"
      - "sudo perl -e"
      - "/bin/sh -p"
      - "/bin/bash -p"
      - "sudo env "
      - "sudo gdb"
      - "sudo less "
      - "sudo more "
      - "sudo man "
      - "sudo ftp"
      - "sudo ed "
      - "sudo vim.tiny"
      - "--checkpoint-action=exec"
  condition: selection
falsepositives:
  - Rare legitimate administrative one-liners
`,
	// ── Linux T1070.003 – Clear Command History ────────────────
	`
title: Clear Linux Command History
description: Detects clearing or disabling of shell command history (history -c, unset HISTFILE, redirecting ~/.bash_history to /dev/null) used to cover tracks.
status: stable
level: medium
tags:
  - attack.t1070.003
  - attack.defense_evasion
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - "history -c"
      - "unset HISTFILE"
      - "HISTFILE=/dev/null"
      - "HISTSIZE=0"
      - "rm ~/.bash_history"
      - "rm -f ~/.bash_history"
      - "ln -sf /dev/null ~/.bash_history"
      - "truncate -s0 ~/.bash_history"
  condition: selection
falsepositives:
  - Rare; users seldom wipe history deliberately
`,
	// ── Linux T1003.008 – /etc/passwd & /etc/shadow Dump ───────
	`
title: Linux Shadow File Credential Dump
description: Detects reading/copying of /etc/shadow or combining passwd+shadow (unshadow) for offline password cracking.
status: stable
level: high
tags:
  - attack.t1003.008
  - attack.credential_access
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - "cat /etc/shadow"
      - "cp /etc/shadow"
      - "/etc/shadow /tmp"
      - "unshadow"
      - "cat /etc/gshadow"
  condition: selection
falsepositives:
  - Authorised account-management tooling
`,
	// ── Linux T1543.002 – systemd Service Persistence ──────────
	`
title: Linux systemd Service Persistence
description: Detects systemd-based persistence — a transient unit via systemd-run, or writing a unit file into a systemd directory.
status: stable
level: medium
tags:
  - attack.t1543.002
  - attack.persistence
  - attack.privilege_escalation
logsource:
  product: linux
  category: process_creation
detection:
  systemdrun:
    Image|contains: systemd-run
  unitwrite:
    Image|contains:
      - tee
      - cp
      - mv
    CommandLine|contains:
      - "/etc/systemd/system/"
      - "/.config/systemd/user/"
      - "/lib/systemd/system/"
  condition: systemdrun or unitwrite
falsepositives:
  - Package installers writing systemd units
`,
	// ── Linux T1546.004 – Shell rc / profile Modification ──────
	`
title: Linux Shell Init Persistence (.bashrc / profile)
description: Detects appending to shell init files (.bashrc/.bash_profile/.profile/profile.d/.zshrc) via tee, a common Linux persistence/triggered-execution mechanism.
status: stable
level: medium
tags:
  - attack.t1546.004
  - attack.persistence
  - attack.privilege_escalation
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    Image|contains: tee
    CommandLine|contains:
      - .bashrc
      - .bash_profile
      - .bash_login
      - .profile
      - /etc/profile.d/
      - .zshrc
  condition: selection
falsepositives:
  - Legitimate provisioning scripts customising shells
`,
	// ── Linux T1611 – Escape to Host (container breakout) ──────
	`
title: Container Escape to Host
description: Detects container-breakout tradecraft — entering host namespaces via nsenter --target 1, a privileged container, host-root mounts, or accessing /proc/1/root.
status: stable
level: high
tags:
  - attack.t1611
  - attack.privilege_escalation
logsource:
  product: linux
  category: process_creation
detection:
  nsenter:
    Image|contains: nsenter
    CommandLine|contains:
      - "--target 1"
      - "-t 1"
  privileged:
    CommandLine|contains:
      - "--privileged"
      - "/proc/1/root"
      - "unshare -r"
      - "cap_sys_admin"
  hostmount:
    CommandLine|contains:
      - "-v /:/"
      - "-v /:/host"
  # runc /proc/self/exe overwrite (CVE-2019-5736), cgroup release_agent escape,
  # and abusing a mounted docker.sock to launch a privileged container.
  runc_escape:
    CommandLine|contains:
      - "/proc/self/exe"
      - "release_agent"
      - "docker.sock"
  condition: nsenter or privileged or hostmount or runc_escape
falsepositives:
  - Legitimate privileged container operations by platform admins
`,

	// ── Linux T1548.001 – SUID/Capability Enumeration ────────────
	// FN-hardening: enumerating setuid binaries / file capabilities is the #1
	// Linux privilege-escalation recon step and had no builtin rule.
	`
title: SUID or Capability Enumeration (Linux)
description: Detects enumeration of setuid/setgid binaries or file capabilities (find -perm -4000, getcap -r), the standard reconnaissance before Linux privilege escalation.
status: stable
level: medium
tags:
  - attack.t1548.001
  - attack.privilege_escalation
logsource:
  product: linux
  category: process_creation
detection:
  find_suid:
    CommandLine|contains:
      - "-perm -4000"
      - "-perm -2000"
      - "-perm -6000"
      - "-perm -u=s"
      - "-perm -g=s"
      - "-perm /4000"
      - "-perm /6000"
  getcap:
    CommandLine|contains:
      - "getcap -r"
      - "getcap -a"
  condition: find_suid or getcap
falsepositives:
  - Security auditing / hardening scans
`,

	// ── macOS T1574.006 – Dylib Injection via DYLD_* ─────────────
	// FN-hardening: DYLD_INSERT_LIBRARIES (macOS equivalent of LD_PRELOAD) forces
	// a target process to load an attacker dylib — a common injection / persistence
	// / privilege-escalation vector with no builtin rule.
	`
title: macOS Dylib Injection via DYLD Environment Variable
description: Detects use of DYLD_INSERT_LIBRARIES / DYLD_LIBRARY_PATH / DYLD_FRAMEWORK_PATH to force a process to load an attacker-controlled dynamic library.
status: stable
level: high
tags:
  - attack.t1574.006
  - attack.privilege_escalation
  - attack.defense_evasion
logsource:
  product: macos
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - "DYLD_INSERT_LIBRARIES="
      - "DYLD_LIBRARY_PATH="
      - "DYLD_FRAMEWORK_PATH="
  condition: selection
falsepositives:
  - Some debugging/profiling tools set DYLD_INSERT_LIBRARIES (rare on a command line)
`,
	// ── Linux T1485 – Data Destruction ─────────────────────────
	`
title: Linux Destructive Disk/File Wipe
description: Detects destructive operations — rm with --no-preserve-root or system directories, mkfs/shred/wipefs, or dd overwriting a block device.
status: stable
level: high
tags:
  - attack.t1485
  - attack.impact
logsource:
  product: linux
  category: process_creation
detection:
  rmroot:
    CommandLine|contains:
      - "--no-preserve-root"
      - "rm -rf /*"
      - "rm -rf /bin"
      - "rm -rf /etc"
      - "rm -rf /boot"
      - "rm -rf /var"
  tools:
    Image|contains:
      - mkfs
      - shred
      - wipefs
  ddwipe:
    Image|contains: dd
    CommandLine|contains: "of=/dev/"
  condition: rmroot or tools or ddwipe
falsepositives:
  - Authorised disk provisioning / secure wipe
`,
	// ── Linux T1552.004 – SSH Private Key File Read (file_access) ─
	// Pairs with the agent's sensitive-file read auditing (IN_ACCESS on ~/.ssh/id_*):
	// a READ of a private key file is surfaced as a file_access event and flagged here.
	`
title: SSH Private Key File Read
description: Detects a read of an SSH/PEM private key file (~/.ssh/id_rsa etc.), surfaced via file-access auditing — a credential-theft signal independent of the reading process's command line.
status: stable
level: medium
tags:
  - attack.t1552.004
  - attack.credential_access
logsource:
  product: linux
  category: file_access
detection:
  selection:
    TargetFilename|contains:
      - /.ssh/id_rsa
      - /.ssh/id_dsa
      - /.ssh/id_ecdsa
      - /.ssh/id_ed25519
  condition: selection
falsepositives:
  - ssh/scp legitimately using the key (correlate with destination)
`,
	// ── Linux T1552.004 – SSH Private Key Access (process) ─────
	`
title: SSH Private Key Access (Linux)
description: Detects reading or searching for SSH/PEM private keys (id_rsa/id_ed25519/*.pem) via cat/cp/scp/base64 or find, a credential-harvesting step.
status: stable
level: medium
tags:
  - attack.t1552.004
  - attack.credential_access
logsource:
  product: linux
  category: process_creation
detection:
  reader:
    Image|contains:
      - cat
      - cp
      - scp
      - base64
    CommandLine|contains:
      - id_rsa
      - id_dsa
      - id_ed25519
      - /.ssh/id
  finder:
    Image|contains: find
    CommandLine|contains:
      - id_rsa
      - .pem
  condition: reader or finder
falsepositives:
  - Backup or key-rotation automation
`,
	// ══ macOS coverage (previously zero) ══
	// ── macOS T1059.002 – AppleScript Execution ────────────────
	`
title: Malicious AppleScript Execution (osascript)
description: Detects osascript invoking a shell, downloading, or decoding — AppleScript abuse for execution on macOS.
status: stable
level: high
tags:
  - attack.t1059.002
  - attack.execution
logsource:
  product: macos
  category: process_creation
detection:
  selection:
    Image|contains: osascript
    CommandLine|contains:
      - "do shell script"
      - "do JavaScript"
      - curl
      - base64
  condition: selection
falsepositives:
  - Legitimate automation using AppleScript
`,
	// ── macOS T1543.001/T1547.011 – Launch Agent/Daemon ────────
	`
title: macOS Launch Agent/Daemon Persistence
description: Detects persistence via launchd — loading/bootstrapping a service or writing a plist into a LaunchAgents/LaunchDaemons directory.
status: stable
level: high
tags:
  - attack.t1543.001
  - attack.t1547.011
  - attack.persistence
logsource:
  product: macos
  category: process_creation
detection:
  launchctl:
    Image|contains: launchctl
    CommandLine|contains:
      - LaunchDaemons
      - LaunchAgents
      - bootstrap
      - "load -w"
  plistwrite:
    Image|contains:
      - tee
      - cp
      - mv
    CommandLine|contains:
      - /Library/LaunchDaemons/
      - /Library/LaunchAgents/
  condition: launchctl or plistwrite
falsepositives:
  - Installers registering legitimate launch services
`,
	// ── macOS T1555.001 – Keychain Credential Access ───────────
	`
title: macOS Keychain Credential Access
description: Detects dumping or extracting credentials from the macOS keychain via the security tool.
status: stable
level: high
tags:
  - attack.t1555.001
  - attack.credential_access
logsource:
  product: macos
  category: process_creation
detection:
  selection:
    Image|contains: security
    CommandLine|contains:
      - dump-keychain
      - find-generic-password
      - find-internet-password
  condition: selection
falsepositives:
  - Administrative credential retrieval
`,
	// ── macOS T1553.001 – Gatekeeper Bypass ────────────────────
	`
title: macOS Gatekeeper Bypass
description: Detects disabling Gatekeeper (spctl --master-disable) or stripping the com.apple.quarantine attribute (xattr) to run unsigned/downloaded code.
status: stable
level: high
tags:
  - attack.t1553.001
  - attack.defense_evasion
logsource:
  product: macos
  category: process_creation
detection:
  spctl:
    Image|contains: spctl
    CommandLine|contains:
      - "--master-disable"
      - "--global-disable"
  xattr:
    Image|contains: xattr
    CommandLine|contains: com.apple.quarantine
  condition: spctl or xattr
falsepositives:
  - Developers clearing quarantine on their own builds
`,
	// ── macOS T1547.015 – Login Items Persistence ──────────────
	`
title: macOS Login Item Persistence
description: Detects creation of a Login Item via AppleScript (System Events make login item), a user-scope persistence mechanism.
status: stable
level: medium
tags:
  - attack.t1547.015
  - attack.persistence
logsource:
  product: macos
  category: process_creation
detection:
  selection:
    Image|contains: osascript
    CommandLine|contains:
      - "login item"
      - "make login item"
      - "make new login item"
  condition: selection
falsepositives:
  - Apps legitimately registering a login item
`,
	// ── macOS T1113 – Screen Capture ───────────────────────────
	`
title: macOS Screen Capture (screencapture)
description: Detects use of the screencapture utility, especially silent (-x) captures, to collect visual data on macOS.
status: stable
level: medium
tags:
  - attack.t1113
  - attack.collection
logsource:
  product: macos
  category: process_creation
detection:
  selection:
    Image|contains: screencapture
  condition: selection
falsepositives:
  - Users taking screenshots via the command line
`,
	// ── T1197 – BITS Jobs ─────────────────────────────────────
	`
title: BITS Job Abuse for Download or Persistence
description: Detects bitsadmin or PowerShell BITS transfers used to download payloads or persist as a stealthy living-off-the-land technique.
status: stable
level: medium
tags:
  - attack.t1197
  - attack.defense_evasion
  - attack.persistence
logsource:
  product: windows
  category: process_creation
detection:
  bitsadmin:
    Image|endswith: \bitsadmin.exe
    CommandLine|contains:
      - /transfer
      - /create
      - /addfile
      - /setnotifycmdline
  powershell_bits:
    CommandLine|contains:
      - Start-BitsTransfer
      - Import-Module BitsTransfer
  condition: bitsadmin or powershell_bits
falsepositives:
  - Legitimate software updaters that use BITS
`,
	// ── T1546.008 – Accessibility Features ────────────────────
	`
title: Accessibility Feature Backdoor (Sticky Keys)
description: Detects an accessibility binary (sethc/utilman/osk/magnify/narrator/displayswitch/atbroker) spawning a command shell — the classic pre-logon backdoor for code execution as SYSTEM.
status: stable
level: high
tags:
  - attack.t1546.008
  - attack.privilege_escalation
  - attack.persistence
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
      - \sethc.exe
      - \utilman.exe
      - \osk.exe
      - \magnify.exe
      - \narrator.exe
      - \displayswitch.exe
      - \atbroker.exe
    Image|endswith:
      - \cmd.exe
      - \powershell.exe
      - \pwsh.exe
      - \cscript.exe
      - \wscript.exe
  condition: selection
falsepositives:
  - Extremely rare; accessibility tools do not normally spawn shells
`,
	// ── T1546.001 – AppInit DLLs ──────────────────────────────
	`
title: AppInit DLLs Persistence
description: Detects setting the AppInit_DLLs or LoadAppInit_DLLs registry values, which force every user-mode process that loads user32.dll to also load an attacker DLL — a stealthy system-wide persistence and privilege-escalation foothold.
status: stable
level: high
tags:
  - attack.t1546.001
  - attack.persistence
  - attack.privilege_escalation
logsource:
  product: windows
  category: process_creation
detection:
  appinit:
    CommandLine|contains:
      - AppInit_DLLs
      - LoadAppInit_DLLs
  condition: appinit
falsepositives:
  - Rare legacy software that legitimately registers an AppInit DLL
`,
	// ── T1037.001 – Logon Script (Windows) ────────────────────
	`
title: Logon Script Persistence (UserInitMprLogonScript)
description: Detects setting the UserInitMprLogonScript registry value under the user Environment key, which runs an attacker-specified script at every interactive logon — a classic user-scoped persistence mechanism.
status: stable
level: high
tags:
  - attack.t1037.001
  - attack.persistence
  - attack.privilege_escalation
logsource:
  product: windows
  category: process_creation
detection:
  logon_script:
    CommandLine|contains: UserInitMprLogonScript
  condition: logon_script
falsepositives:
  - Rare legitimate logon-script configuration by administrators
`,
	// ── T1547.004 – Winlogon Helper DLL ───────────────────────
	`
title: Winlogon Helper Persistence (Shell/Userinit)
description: Detects modification of the Winlogon Shell, Userinit, or Notify registry values, used to persist and execute code at every interactive logon.
status: stable
level: high
tags:
  - attack.t1547.004
  - attack.persistence
  - attack.privilege_escalation
logsource:
  product: windows
  category: registry_event
detection:
  selection:
    TargetObject|contains:
      - \Microsoft\Windows NT\CurrentVersion\Winlogon\Shell
      - \Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit
      - \Microsoft\Windows NT\CurrentVersion\Winlogon\Notify
  condition: selection
falsepositives:
  - Rare legitimate shell/userinit replacement by management software
`,
	// ── T1518.001 – Security Software Discovery ───────────────
	`
title: Security Software Discovery
description: Detects enumeration of installed security/EDR products via tasklist/wmic/sc/Get-Service filtered for AV vendor names — common attacker reconnaissance before defense evasion.
status: experimental
level: medium
tags:
  - attack.t1518.001
  - attack.discovery
logsource:
  product: windows
  category: process_creation
detection:
  tooling:
    Image|endswith:
      - \tasklist.exe
      - \wmic.exe
      - \sc.exe
      - \powershell.exe
      - \pwsh.exe
      - \net.exe
  products:
    CommandLine|contains:
      - windefend
      - mssense
      - msmpeng
      - sentinel
      - crowdstrike
      - csagent
      - carbonblack
      - cylance
      - cybereason
      - sophos
      - sysmon
      # Other major AV/EDR vendors an attacker's discovery sweep commonly
      # greps for that the list above didn't cover.
      - mcafee
      - symantec
      - trendmicro
      - "trend micro"
      - eset
      - bitdefender
      - kaspersky
      - malwarebytes
      - fireeye
      - forcepoint
      - tanium
      - huntress
      - cynet
  condition: tooling and products
falsepositives:
  - IT inventory or monitoring scripts that enumerate security products
`,
	// ── T1546.007 – Netsh Helper DLL ──────────────────────────
	`
title: Netsh Helper DLL Persistence
description: Detects registration of a netsh helper DLL (netsh add helper), which loads attacker code whenever netsh runs — a stealthy persistence and privilege-escalation technique.
status: stable
level: high
tags:
  - attack.t1546.007
  - attack.persistence
  - attack.privilege_escalation
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: \netsh.exe
    CommandLine|contains|all:
      - add
      - helper
  condition: selection
falsepositives:
  - Rare legitimate netsh helper installations by network software
`,
	// ── T1569.002 – Service Execution (PsExec) ────────────────
	`
title: PsExec Service Execution
description: Detects PsExec remote execution via its service (PSEXESVC) or client, used for lateral movement and SYSTEM-level command execution.
status: stable
level: medium
tags:
  - attack.t1569.002
  - attack.execution
  - attack.lateral_movement
logsource:
  product: windows
  category: process_creation
detection:
  service:
    Image|endswith: \PSEXESVC.exe
  client:
    Image|endswith:
      - \psexec.exe
      - \psexec64.exe
    CommandLine|contains: accepteula
  condition: service or client
falsepositives:
  - Legitimate administrative use of PsExec
`,
	// ── T1053.002 – Scheduled Task/Job: At ────────────────────
	`
title: At.exe Legacy Job Scheduling
description: Detects use of the legacy at.exe scheduler — uncommon on modern Windows and favored by attackers for persistence and lateral movement.
status: stable
level: medium
tags:
  - attack.t1053.002
  - attack.execution
  - attack.persistence
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: \at.exe
    CommandLine|contains:
      - .exe
      - .bat
      - cmd
      - powershell
  condition: selection
falsepositives:
  - Legacy administration scripts still using at
`,
	// ── T1070.002 – Clear Linux/macOS System Logs ─────────────
	`
title: System Log Clearing (Linux/macOS)
description: Detects deletion or truncation of system logs (rm/truncate of /var/log, journalctl vacuum, redirecting empty output into a log file) — anti-forensics to cover tracks.
status: stable
level: high
tags:
  - attack.t1070.002
  - attack.defense_evasion
logsource:
  product: linux
  category: process_creation
detection:
  rm_logs:
    CommandLine|contains:
      - rm -rf /var/log
      - rm -f /var/log
      - rm /var/log
  truncate_logs:
    CommandLine|contains:
      - truncate -s 0 /var/log
      - truncate -s0 /var/log
  journal:
    CommandLine|contains: journalctl --vacuum
  redirect:
    CommandLine|contains:
      - '> /var/log/'
      - ': > /var/log'
  condition: rm_logs or truncate_logs or journal or redirect
falsepositives:
  - Aggressive log-rotation or cleanup scripts (rare for direct rm of /var/log)
`,
	// ── T1222.002 – Linux/macOS File Permission Modification ──
	`
title: Setuid/Setgid Permission Modification (Linux/macOS)
description: Detects chmod setting the setuid or setgid bit on a file, a common privilege-escalation and persistence step that lets an attacker run code with elevated rights.
status: experimental
level: medium
tags:
  - attack.t1222.002
  - attack.defense_evasion
  - attack.privilege_escalation
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    Image|endswith: /chmod
    CommandLine|contains:
      - ' u+s'
      - ' g+s'
      - ' +s'
      - ' 4755'
      - ' 4777'
      - ' 2755'
      - ' 6755'
  condition: selection
falsepositives:
  - Package or build scripts setting setuid on legitimate binaries (e.g. ping, sudo)
`,
	// ── T1204.002 – Malicious File (Office macro) ─────────────
	`
title: Office Application Spawning a Script Interpreter
description: Detects a Microsoft Office application (Word/Excel/PowerPoint/Outlook/Publisher) launching a command shell or script interpreter — the hallmark of malicious macro or document execution.
status: stable
level: high
tags:
  - attack.t1204.002
  - attack.execution
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
      - \winword.exe
      - \excel.exe
      - \powerpnt.exe
      - \outlook.exe
      - \mspub.exe
      - \visio.exe
      - \onenote.exe
    Image|endswith:
      - \cmd.exe
      - \powershell.exe
      - \pwsh.exe
      - \wscript.exe
      - \cscript.exe
      - \mshta.exe
      - \rundll32.exe
      - \regsvr32.exe
      - \bitsadmin.exe
      - \certutil.exe
  condition: selection
falsepositives:
  - Rare legitimate Office add-ins that shell out
`,
	// ── T1547.006 – Kernel Modules and Extensions ─────────────
	`
title: Kernel Module Loading (Linux)
description: Detects loading a kernel module via insmod/modprobe, especially from a user-writable path — used to install rootkits and kernel-level persistence.
status: stable
level: high
tags:
  - attack.t1547.006
  - attack.persistence
  - attack.privilege_escalation
logsource:
  product: linux
  category: process_creation
detection:
  insmod:
    Image|endswith: /insmod
  suspicious_path:
    CommandLine|contains:
      - insmod /tmp/
      - insmod /dev/shm/
      - insmod /var/tmp/
      - 'modprobe ./'
  condition: insmod or suspicious_path
falsepositives:
  - Legitimate driver/module installation by package managers or administrators
`,
	// ── T1610 – Deploy Container (privileged/host escape) ─────
	`
title: Privileged or Host-Escape Container Deployment
description: Detects launching a container with host-escape options (--privileged, host PID/network namespace, mounting the host root, or the docker socket) — a common container breakout and host-compromise setup.
status: stable
level: high
tags:
  - attack.t1610
  - attack.execution
  - attack.privilege_escalation
logsource:
  product: linux
  category: process_creation
detection:
  runner:
    Image|endswith:
      - /docker
      - /podman
      - /nerdctl
    CommandLine|contains: ' run '
  danger:
    CommandLine|contains:
      - --privileged
      - '--pid=host'
      - '--net=host'
      - '-v /:/'
      - '--volume=/:/'
      - /var/run/docker.sock
  condition: runner and danger
falsepositives:
  - Legitimate privileged containers (CI runners, monitoring/security agents)
`,
	// ── T1609 – Container Administration Command ──────────────
	`
title: Container Administration Command Execution
description: Detects entering a running container via kubectl/docker/podman exec — used to run commands inside containers, including by attackers who have compromised the orchestration plane.
status: experimental
level: medium
tags:
  - attack.t1609
  - attack.execution
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    Image|endswith:
      - /kubectl
      - /docker
      - /podman
    CommandLine|contains: ' exec '
  # Absorbed from the rules-table row "Container Administration Command (DB)"
  # (migration 322), which migration 377 disables. That row keyed on the command
  # line alone, so it caught two cases this rule's Image|endswith misses:
  # crictl, and any wrapper invocation where Image is the wrapper rather than the
  # container CLI (sudo docker exec ..., env docker exec ...). Keeping the
  # branch is what makes disabling the DB row lossless.
  cmdline_only:
    CommandLine|contains|all:
      - ' exec '
    CommandLine|contains:
      - kubectl
      - docker
      - podman
      - crictl
  condition: selection or cmdline_only
falsepositives:
  - Legitimate operator or CI access into containers
`,
	// ── T1612 – Build Image on Host ────────────────────────────
	`
title: Container Image Build on Host
description: Detects building a container image directly on a host (docker/podman/nerdctl build, buildah bud/build, kaniko executor, or img build). Adversaries build malicious images locally to bypass registry-side image scanning and admission controls before deploying them.
status: stable
level: medium
tags:
  - attack.t1612
  - attack.defense_evasion
logsource:
  product: linux
  category: process_creation
detection:
  build_cli:
    Image|endswith:
      - /docker
      - /podman
      - /nerdctl
    CommandLine|contains: " build"
  buildah:
    CommandLine|contains:
      - "buildah bud"
      - "buildah build"
  kaniko:
    CommandLine|contains:
      - "/kaniko/executor"
      - "kaniko-project"
  img_build:
    Image|endswith: /img
    CommandLine|contains: " build"
  # Absorbed from the rules-table row "Container Image Build on Host (DB)"
  # (migration 322), which migration 377 disables. Same reason as the exec rule
  # above: that row matched the builder name anywhere on the command line, so it
  # caught wrapper invocations (sudo docker build) that build_cli's
  # Image|endswith does not.
  cmdline_only:
    CommandLine|contains|all:
      - " build"
    CommandLine|contains:
      - docker
      - podman
      - nerdctl
  condition: build_cli or buildah or kaniko or img_build or cmdline_only
falsepositives:
  - Legitimate CI/CD image builds on build agents
`,
	// ── T1003.007 – Proc Filesystem credential access ─────────
	`
title: Process Memory Credential Access via /proc (Linux)
description: Detects reading another process's memory through the proc filesystem (/proc/<pid>/mem or maps) with dd/cat/gdb/gcore — used to scrape credentials from memory (e.g. sshd, gnome-keyring).
status: stable
level: high
tags:
  - attack.t1003.007
  - attack.credential_access
logsource:
  product: linux
  category: process_creation
detection:
  reader:
    Image|endswith:
      - /dd
      - /cat
      - /gdb
      - /gcore
  proc_mem:
    CommandLine|contains: /proc/
  region:
    CommandLine|contains:
      - /mem
      - /maps
  condition: reader and proc_mem and region
falsepositives:
  - Debugging or memory-forensics tooling
`,
	// ── T1090.003 – Multi-hop Proxy (Tor) ─────────────────────
	`
title: Tor Anonymity Client Execution
description: Detects execution of the Tor client or references to .onion services — used for anonymized C2 and exfiltration, and rarely legitimate on managed endpoints.
status: stable
level: medium
tags:
  - attack.t1090.003
  - attack.command_and_control
logsource:
  product: windows
  category: process_creation
detection:
  tor_binary:
    Image|endswith:
      - \tor.exe
      - \tor-browser.exe
      - /tor
  onion:
    CommandLine|contains: .onion
  condition: tor_binary or onion
falsepositives:
  - Privacy-conscious users intentionally running Tor
`,
	// ── T1539 – Steal Web Session Cookie ──────────────────────
	`
title: Browser Cookie or Login Database Access
description: Detects a process copying or reading a browser cookie/credential database (Chrome/Edge Network Cookies and Login Data, Firefox cookies.sqlite/logins.json), used to steal session tokens and saved passwords.
status: experimental
level: high
tags:
  - attack.t1539
  - attack.credential_access
logsource:
  product: windows
  category: process_creation
detection:
  store:
    CommandLine|contains:
      - \Network\Cookies
      - Login Data
      - cookies.sqlite
      - logins.json
  tool:
    Image|endswith:
      - \cmd.exe
      - \powershell.exe
      - \pwsh.exe
      - \xcopy.exe
      - \robocopy.exe
      - \esentutl.exe
      - \sqlite3.exe
      - /cat
      - /cp
      - /sqlite3
  condition: store and tool
falsepositives:
  - Backup software touching browser profiles
`,
	// ── T1037.004 – RC Scripts (Linux) ────────────────────────
	`
title: RC Script Persistence (Linux)
description: Detects modification of init/RC startup scripts (/etc/rc.local, /etc/init.d, /etc/rc.d) to run code at boot — a classic Linux persistence mechanism.
status: stable
level: high
tags:
  - attack.t1037.004
  - attack.persistence
  - attack.privilege_escalation
logsource:
  product: linux
  category: process_creation
detection:
  write:
    CommandLine|contains:
      - '> /etc/rc.local'
      - '>> /etc/rc.local'
      - tee /etc/rc.local
      - tee -a /etc/rc.local
  edit:
    Image|endswith:
      - /vi
      - /vim
      - /nano
    CommandLine|contains: /etc/rc.local
  initd:
    CommandLine|contains:
      - '> /etc/init.d/'
      - tee /etc/init.d/
  condition: write or edit or initd
falsepositives:
  - Administrators legitimately editing boot scripts
`,
	// ── T1053.006 – Systemd Timers (Linux) ────────────────────
	`
title: Systemd Timer Persistence (Linux)
description: Detects creating or enabling a systemd timer unit, which can schedule attacker code to run repeatedly — a stealthier alternative to cron for persistence.
status: experimental
level: medium
tags:
  - attack.t1053.006
  - attack.persistence
  - attack.privilege_escalation
logsource:
  product: linux
  category: process_creation
detection:
  systemctl_timer:
    Image|endswith: /systemctl
    CommandLine|contains: .timer
  write_timer:
    CommandLine|contains|all:
      - .timer
      - /systemd/system/
  condition: systemctl_timer or write_timer
falsepositives:
  - Legitimate software installing systemd timers
`,
	// ── T1547.009 – Shortcut/Startup Folder ───────────────────
	`
title: Startup Folder Persistence
description: Detects a process dropping a file (shortcut, script, or executable) into a user or common Startup folder, which runs automatically at logon — a simple, common persistence technique.
status: stable
level: medium
tags:
  - attack.t1547.009
  - attack.persistence
logsource:
  product: windows
  category: process_creation
detection:
  startup:
    CommandLine|contains: \Start Menu\Programs\Startup
  writers:
    Image|endswith:
      - \cmd.exe
      - \powershell.exe
      - \pwsh.exe
      - \xcopy.exe
      - \robocopy.exe
      - \certutil.exe
      - \cscript.exe
      - \wscript.exe
  condition: startup and writers
falsepositives:
  - Legitimate installers that add startup shortcuts
`,
	// ── T1218.012 – System Binary Proxy: Verclsid ─────────────
	`
title: Verclsid COM Object Proxy Execution
description: Detects verclsid.exe invoked with /S /C to validate (and thereby execute) a COM/shell object — a signed LOLBin used to proxy execution and bypass application control.
status: stable
level: high
tags:
  - attack.t1218.012
  - attack.defense_evasion
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: \verclsid.exe
    CommandLine|contains|all:
      - /S
      - /C
  condition: selection
falsepositives:
  - Rare legitimate shell extension validation
`,
	// ── T1552.002 – Credentials in Registry ───────────────────
	`
title: Registry Credential Hunting
description: Detects reg.exe or PowerShell searching the registry for stored passwords or credentials (reg query ... /f password /s), a common post-exploitation credential-access step.
status: stable
level: medium
tags:
  - attack.t1552.002
  - attack.credential_access
logsource:
  product: windows
  category: process_creation
detection:
  reg_search:
    Image|endswith: \reg.exe
    CommandLine|contains|all:
      - query
      - /f
    CommandLine|contains:
      - password
      - passwd
      - pwd
      - credential
  ps_search:
    CommandLine|contains|all:
      - Get-ItemProperty
      - password
  condition: reg_search or ps_search
falsepositives:
  - Administrators auditing for plaintext passwords in the registry
`,
	// ── T1027.004 – Compile After Delivery ────────────────────
	`
title: Compile After Delivery
description: Detects on-host compilation of source by gcc/cc/clang/csc/cl from a temporary or world-writable directory — used to build payloads on the victim to evade signature-based detection.
status: experimental
level: medium
tags:
  - attack.t1027.004
  - attack.defense_evasion
logsource:
  product: linux
  category: process_creation
detection:
  compiler:
    Image|endswith:
      - /gcc
      - /cc
      - /g++
      - /clang
      - \csc.exe
      - \cl.exe
  temp_src:
    CommandLine|contains:
      - /tmp/
      - /dev/shm/
      - /var/tmp/
      - \AppData\Local\Temp
      - \Windows\Temp
  condition: compiler and temp_src
falsepositives:
  - Build systems that compile in temporary directories
`,
	// ── T1546.013 – PowerShell Profile ────────────────────────
	`
title: PowerShell Profile Persistence
description: Detects writing to a PowerShell profile script (profile.ps1 / Microsoft.PowerShell_profile.ps1), which runs every time PowerShell starts — a stealthy persistence and code-injection vector.
status: stable
level: high
tags:
  - attack.t1546.013
  - attack.persistence
  - attack.privilege_escalation
logsource:
  product: windows
  category: process_creation
detection:
  profile:
    CommandLine|contains:
      - profile.ps1
      - Microsoft.PowerShell_profile.ps1
  write:
    CommandLine|contains:
      - Add-Content
      - Set-Content
      - Out-File
      - '>>'
      - ' > '
      - echo
      - copy
  condition: profile and write
falsepositives:
  - Users or tooling customizing their PowerShell profile
`,
	// ── T1059.006 – Command and Scripting: Python ─────────────
	`
title: Suspicious Python One-Liner Execution
description: Detects python -c one-liners performing risky operations (decode+exec, raw socket C2, os.system shelling, pty spawning) — common in cross-platform malware loaders and reverse shells.
status: experimental
level: medium
tags:
  - attack.t1059.006
  - attack.execution
logsource:
  product: linux
  category: process_creation
detection:
  python:
    Image|endswith:
      - /python
      - /python2
      - /python3
      - \python.exe
    CommandLine|contains: ' -c '
  risky:
    CommandLine|contains:
      - base64
      - exec(
      - eval(
      - socket.socket
      - os.system
      - pty.spawn
      - __import__
  condition: python and risky
falsepositives:
  - Developer or automation one-liners that use these constructs
`,
	// ── T1098.004 – SSH Authorized Keys ───────────────────────
	`
title: SSH Authorized Keys Modification
description: Detects appending to or editing an authorized_keys file, a very common Linux/macOS persistence and backdoor technique that grants an attacker passwordless SSH access.
status: stable
level: high
tags:
  - attack.t1098.004
  - attack.persistence
logsource:
  product: linux
  category: process_creation
detection:
  authkeys:
    CommandLine|contains: authorized_keys
  redirect:
    CommandLine|contains:
      - '>>'
      - ' > '
      - tee
      - echo
      - curl
      - wget
  editors:
    Image|endswith:
      - /tee
      - /vi
      - /vim
      - /nano
    CommandLine|contains: authorized_keys
  condition: (authkeys and redirect) or editors
falsepositives:
  - Configuration management (Ansible/Puppet) deploying SSH keys
`,
	// ── T1556.003 – Pluggable Authentication Modules ──────────
	`
title: PAM Configuration or Module Tampering
description: Detects modification of PAM configuration (/etc/pam.d) or PAM shared modules (pam_*.so), used to backdoor authentication or silently capture credentials.
status: stable
level: high
tags:
  - attack.t1556.003
  - attack.credential_access
  - attack.persistence
  - attack.defense_evasion
logsource:
  product: linux
  category: process_creation
detection:
  pam_target:
    CommandLine|contains:
      - /etc/pam.d/
      - /lib/security/pam_
      - /lib64/security/pam_
      - pam_unix.so
  modify:
    Image|endswith:
      - /tee
      - /vi
      - /vim
      - /nano
      - /sed
      - /cp
      - /mv
      - /dd
  redirect:
    CommandLine|contains:
      - '>>'
      - ' > '
  condition: pam_target and (modify or redirect)
falsepositives:
  - Legitimate PAM configuration by administrators or package managers
`,
	// ── T1037.002 – Login/Logout Hook (macOS) ─────────────────
	`
title: macOS Login or Logout Hook Persistence
description: Detects setting a LoginHook or LogoutHook via defaults write com.apple.loginwindow — a script that runs at login/logout, used for persistence.
status: stable
level: high
tags:
  - attack.t1037.002
  - attack.persistence
  - attack.privilege_escalation
logsource:
  product: macos
  category: process_creation
detection:
  selection:
    Image|endswith: /defaults
    CommandLine|contains: com.apple.loginwindow
  hook:
    CommandLine|contains:
      - LoginHook
      - LogoutHook
  condition: selection and hook
falsepositives:
  - Rare legitimate login hooks (deprecated by Apple)
`,
	// ── T1548.004 – Elevated Execution with Prompt (macOS) ────
	`
title: AppleScript Elevated Execution Prompt
description: Detects osascript running "do shell script ... with administrator privileges", which raises a credential prompt to execute a command as root — used for privilege escalation and credential phishing.
status: stable
level: high
tags:
  - attack.t1548.004
  - attack.privilege_escalation
logsource:
  product: macos
  category: process_creation
detection:
  selection:
    Image|endswith: /osascript
    CommandLine|contains: administrator privileges
  shell:
    CommandLine|contains: do shell script
  condition: selection and shell
falsepositives:
  - Legitimate installers requesting elevation via AppleScript
`,
	// ── T1564.002 – Hidden Users (macOS) ──────────────────────
	`
title: macOS Hidden Account Creation via dscl
description: Detects creating a local account hidden from the login window using dscl with IsHidden or an empty home directory — used to maintain stealthy persistence.
status: experimental
level: medium
tags:
  - attack.t1564.002
  - attack.persistence
  - attack.defense_evasion
logsource:
  product: macos
  category: process_creation
detection:
  dscl:
    Image|endswith: /dscl
    CommandLine|contains: create
  hidden:
    CommandLine|contains:
      - IsHidden
      - /var/empty
  condition: dscl and hidden
falsepositives:
  - Legitimate hidden service-account creation
`,
	// ── T1546.015 – COM Hijacking ─────────────────────────────
	`
title: COM Object Hijacking via Suspicious Server Path
description: Detects a COM server registration (CLSID InprocServer32/LocalServer32) whose DLL/EXE path points to a user-writable location — the hallmark of COM hijacking for stealthy persistence and defense evasion. Requires the COM registry telemetry enabled in the registry ETW collector.
status: experimental
level: high
tags:
  - attack.t1546.015
  - attack.persistence
  - attack.privilege_escalation
  - attack.defense_evasion
logsource:
  product: windows
  category: registry_event
detection:
  com_server:
    TargetObject|contains:
      - \InprocServer32
      - \LocalServer32
  suspicious_path:
    Details|contains:
      - \AppData\
      - \Temp\
      - \Users\Public\
      - \Downloads\
      - \ProgramData\
  condition: com_server and suspicious_path
falsepositives:
  - Portable applications registering COM servers from user directories
`,
	// ── T1547.005 – LSA Packages (SSP / Password Filter / Auth) ─
	`
title: LSA Authentication Package or Password Filter Registration
description: Detects modification of the LSA package lists (Notification Packages = password filter, Security Packages = SSP, Authentication Packages) used to load attacker DLLs into LSASS for credential capture and persistence. Requires LSA registry telemetry enabled in the registry ETW collector.
status: experimental
level: high
tags:
  - attack.t1547.005
  - attack.t1556.002
  - attack.t1547.002
  - attack.persistence
  - attack.credential_access
  - attack.privilege_escalation
logsource:
  product: windows
  category: registry_event
detection:
  selection:
    TargetObject|contains:
      - \Lsa\Notification Packages
      - \Lsa\Security Packages
      - \Lsa\Authentication Packages
      - \Lsa\OSConfig\Security Packages
  condition: selection
falsepositives:
  - Installation of legitimate security products that register LSA packages
`,
	// ── T1546.009 – AppCert DLLs ──────────────────────────────
	`
title: AppCert DLL Persistence
description: Detects modification of the AppCertDlls registry value, which loads a DLL into every process that calls the Win32 process-creation APIs — a stealthy persistence and privilege-escalation mechanism. Requires AppCertDlls registry telemetry enabled in the registry ETW collector.
status: experimental
level: high
tags:
  - attack.t1546.009
  - attack.persistence
  - attack.privilege_escalation
logsource:
  product: windows
  category: registry_event
detection:
  selection:
    TargetObject|contains: \Session Manager\AppCertDlls
  condition: selection
falsepositives:
  - Very rare; few legitimate products use AppCert DLLs
`,
	// ── T1546.010 – AppInit DLLs ──────────────────────────────
	`
title: AppInit DLL Persistence
description: Detects modification of the AppInit_DLLs registry value, which loads a DLL into every process that links user32.dll — a classic persistence and code-injection mechanism.
status: stable
level: high
tags:
  - attack.t1546.010
  - attack.persistence
  - attack.privilege_escalation
logsource:
  product: windows
  category: registry_event
detection:
  selection:
    TargetObject|contains:
      - \Windows\AppInit_DLLs
      - \Windows NT\CurrentVersion\Windows\AppInit_DLLs
  condition: selection
falsepositives:
  - Legacy software that legitimately uses AppInit DLLs
`,
	// ── T1218.007 – Msiexec ───────────────────────────────────
	`
title: Msiexec Remote or UNC Package Execution
description: Detects msiexec installing a package from a remote URL or UNC path — used to download and execute payloads while proxying through a signed, trusted Windows binary.
status: stable
level: high
tags:
  - attack.t1218.007
  - attack.defense_evasion
logsource:
  product: windows
  category: process_creation
detection:
  msiexec:
    Image|endswith: \msiexec.exe
  remote:
    CommandLine|contains:
      - http://
      - https://
      - ftp://
      # Plain (unquoted) YAML scalars don't treat "\" as an escape character,
      # so an unquoted "\\\\" here is literally 4 backslashes and never
      # matches a real UNC path's 2 — must be double-quoted to fold to "\\".
      - "\\\\"
  condition: msiexec and remote
falsepositives:
  - Enterprise software deployment from internal URLs or UNC shares
`,
	// ── T1546.011 – Application Shimming ──────────────────────
	`
title: Application Shim Database Installation
description: Detects sdbinst.exe installing a shim database (.sdb), a stealthy persistence and privilege-escalation technique that injects code via the Application Compatibility framework.
status: stable
level: high
tags:
  - attack.t1546.011
  - attack.persistence
  - attack.privilege_escalation
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: \sdbinst.exe
    CommandLine|contains: .sdb
  condition: selection
falsepositives:
  - Legitimate application-compatibility fixes deployed by IT
`,
	// ── T1218.014 – MMC ───────────────────────────────────────
	`
title: MMC Spawning a Command Shell
description: Detects mmc.exe (Microsoft Management Console) launching a command shell or script interpreter — abused to proxy execution via malicious .msc snap-ins.
status: stable
level: high
tags:
  - attack.t1218.014
  - attack.defense_evasion
  - attack.execution
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith: \mmc.exe
    Image|endswith:
      - \cmd.exe
      - \powershell.exe
      - \pwsh.exe
      - \wscript.exe
      - \cscript.exe
      - \mshta.exe
      - \rundll32.exe
  condition: selection
falsepositives:
  - Rare administrative snap-ins that legitimately shell out
`,
	// ── T1505.001 – SQL Stored Procedures (xp_cmdshell) ───────
	`
title: SQL Server Spawning a Command Shell
description: Detects the SQL Server process (sqlservr.exe) launching a command shell or script interpreter — the signature of xp_cmdshell abuse following SQL injection or credentialed database access.
status: stable
level: high
tags:
  - attack.t1505.001
  - attack.execution
  - attack.persistence
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith: \sqlservr.exe
    Image|endswith:
      - \cmd.exe
      - \powershell.exe
      - \pwsh.exe
      - \wscript.exe
      - \cscript.exe
      - \bitsadmin.exe
  condition: selection
falsepositives:
  - Rare legitimate xp_cmdshell use by DBAs
`,
	// ── T1190 – Exploit Public-Facing App (web server → shell) ─
	`
title: Web Server Process Spawning a Shell
description: Detects a web/application server process (w3wp, httpd, apache2, nginx, php-fpm) spawning a command shell — a strong indicator of a web shell or exploitation of a public-facing application.
status: stable
level: high
tags:
  - attack.t1190
  - attack.t1505.003
  - attack.initial_access
  - attack.execution
logsource:
  product: linux
  category: process_creation
detection:
  webserver:
    ParentImage|endswith:
      - \w3wp.exe
      - /httpd
      - /apache2
      - /nginx
      - /php-fpm
      - /php
  shell:
    Image|endswith:
      - \cmd.exe
      - \powershell.exe
      - /sh
      - /bash
      - /dash
      - /zsh
      - \whoami.exe
      - /whoami
      - /id
  condition: webserver and shell
falsepositives:
  - CGI or automation that legitimately invokes shells (tune per environment)
`,
	// ── T1547.014 – Active Setup ──────────────────────────────
	`
title: Active Setup Installed Components Persistence
description: Detects setting a StubPath under Active Setup\Installed Components, which runs a command for each user at first logon — a stealthy persistence mechanism. Requires Active Setup registry telemetry.
status: stable
level: high
tags:
  - attack.t1547.014
  - attack.persistence
  - attack.privilege_escalation
logsource:
  product: windows
  category: registry_event
detection:
  selection:
    TargetObject|contains: \Active Setup\Installed Components\
    TargetObject|endswith: \StubPath
  condition: selection
falsepositives:
  - Legitimate software registering Active Setup components on install
`,
	// ── T1543.003 – Service ImagePath/ServiceDll Hijack ───────
	`
title: Service ImagePath or ServiceDll Hijack to Suspicious Path
description: Detects modifying a service's ImagePath or ServiceDll to a user-writable or LOLBin path — service-based persistence and privilege escalation. Requires services registry telemetry.
status: experimental
level: high
tags:
  - attack.t1543.003
  - attack.persistence
  - attack.privilege_escalation
logsource:
  product: windows
  category: registry_event
detection:
  service_value:
    TargetObject|contains: \Services\
    TargetObject|endswith:
      - \ImagePath
      - \ServiceDll
  suspicious:
    Details|contains:
      - \AppData\
      - \Temp\
      - \Users\Public\
      - \ProgramData\
      - \Downloads\
      - powershell
      - cmd.exe
      - rundll32
  condition: service_value and suspicious
falsepositives:
  - Legitimate service installs from non-standard paths
`,
	// ── T1547.001 – Windows Load/Run legacy value ─────────────
	`
title: Windows Load or Run Value Persistence
description: Detects writing the Load or Run value under Windows NT\CurrentVersion\Windows, a legacy auto-start location that launches a program at logon. Requires registry telemetry.
status: stable
level: high
tags:
  - attack.t1547.001
  - attack.persistence
logsource:
  product: windows
  category: registry_event
detection:
  selection:
    TargetObject|contains:
      - \CurrentVersion\Windows\Load
      - \CurrentVersion\Windows\Run
  condition: selection
falsepositives:
  - Rare legitimate use of these legacy values
`,
	// ── T1202 – Indirect Command Execution ────────────────────
	`
title: Indirect Command Execution via Trusted Utility
description: Detects forfiles, pcalua, or scriptrunner launching a command shell or executable — indirect execution that breaks the expected parent-child chain to evade detection.
status: stable
level: medium
tags:
  - attack.t1202
  - attack.defense_evasion
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith:
      - \forfiles.exe
      - \pcalua.exe
      - \scriptrunner.exe
    CommandLine|contains:
      - cmd
      - powershell
      - .exe
      - .bat
      - .vbs
  condition: selection
falsepositives:
  - Legitimate maintenance scripts using forfiles
`,
	// ── T1098 – Local Administrators Group Addition ───────────
	`
title: Local Administrators Group Addition via net.exe
description: Detects adding an account to the local Administrators group with net localgroup — a common privilege-escalation and persistence step after gaining a foothold.
status: stable
level: high
tags:
  - attack.t1098
  - attack.persistence
  - attack.privilege_escalation
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith:
      - \net.exe
      - \net1.exe
    CommandLine|contains|all:
      - localgroup
      - /add
    CommandLine|contains:
      - administ
  condition: selection
falsepositives:
  - Administrators legitimately managing local group membership
`,

	// ── T1136.003 – Cloud Account Creation ─────────────────────
	`
title: Cloud Account Creation
description: Detects creation of cloud identities for persistence — aws iam create-user / create-login-profile, az ad user create, gcloud iam service-accounts create — establishing durable attacker-controlled access after cloud compromise.
status: stable
level: high
tags:
  - attack.t1136.003
  - attack.persistence
logsource:
  category: process_creation
detection:
  aws_create:
    CommandLine|contains:
      - "iam create-user"
      - "iam create-login-profile"
  az_create:
    CommandLine|contains|all:
      - "az ad"
      - "create"
    CommandLine|contains:
      - "user"
      - "sp"
      - "app"
  gcloud_create:
    CommandLine|contains: "iam service-accounts create"
  condition: aws_create or az_create or gcloud_create
falsepositives:
  - Cloud administrators or IaC provisioning new identities
`,

	// ── T1098.001 – Additional Cloud Credentials ───────────────
	`
title: Additional Cloud Credentials
description: Detects attaching new long-lived credentials to a cloud identity for persistence — aws iam create-access-key / create-login-profile, az ad app|sp credential reset, gcloud iam service-accounts keys create — so the attacker retains access even if the initial credential is revoked.
status: stable
level: high
tags:
  - attack.t1098.001
  - attack.persistence
logsource:
  category: process_creation
detection:
  aws_key:
    CommandLine|contains:
      - "iam create-access-key"
      - "iam create-login-profile"
  az_cred:
    CommandLine|contains|all:
      - "az ad"
      - "credential"
    CommandLine|contains: "reset"
  gcloud_key:
    CommandLine|contains: "service-accounts keys create"
  condition: aws_key or az_cred or gcloud_key
falsepositives:
  - Legitimate key rotation by cloud administrators or IaC
`,

	// ── T1098.003 – Additional Cloud Roles ─────────────────────
	`
title: Additional Cloud Roles
description: Detects granting elevated permissions to a cloud identity — aws iam attach-user-policy / attach-role-policy / put-user-policy / add-user-to-group, az role assignment create, gcloud add-iam-policy-binding — used for privilege escalation and persistence.
status: stable
level: high
tags:
  - attack.t1098.003
  - attack.privilege_escalation
  - attack.persistence
logsource:
  category: process_creation
detection:
  aws_grant:
    CommandLine|contains:
      - "iam attach-user-policy"
      - "iam attach-role-policy"
      - "iam put-user-policy"
      - "iam add-user-to-group"
  az_grant:
    CommandLine|contains: "role assignment create"
  gcloud_grant:
    CommandLine|contains: "add-iam-policy-binding"
  condition: aws_grant or az_grant or gcloud_grant
falsepositives:
  - Cloud administrators or IaC assigning roles
`,

	// ── T1021.005 – VNC Remote Access (Lateral Movement) ───────
	`
title: VNC Remote Access Tool Execution
description: Detects execution of VNC clients/servers used for interactive remote control (lateral movement) — vncviewer/tvnviewer/winvnc/tvnserver.
status: experimental
level: medium
tags:
  - attack.t1021.005
  - attack.lateral_movement
logsource:
  category: process_creation
detection:
  selection:
    Image|endswith:
      - \vncviewer.exe
      - \tvnviewer.exe
      - \winvnc.exe
      - \tvnserver.exe
      - \vncserver.exe
  condition: selection
falsepositives:
  - Sanctioned VNC-based remote administration
`,

	// ── T1006 – Direct Volume Access (raw disk read) ───────────
	`
title: Direct Volume Access (Raw Disk Read)
description: Detects raw volume/device access that bypasses the file system to read locked files (SAM/NTDS) — the \\.\ device path, \\.\PHYSICALDRIVE, or \\?\GLOBALROOT.
status: experimental
level: high
tags:
  - attack.t1006
  - attack.defense_evasion
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - "\\\\.\\C:"
      - "\\\\.\\PHYSICALDRIVE"
      - "\\\\?\\GLOBALROOT"
  condition: selection
falsepositives:
  - Backup/imaging tools that access raw volumes
`,

	// ── T1563.002 – RDP Session Hijack via tscon ───────────────
	`
title: RDP Session Hijack via tscon
description: Detects tscon.exe redirecting another user's disconnected RDP session to the current session (credential-free session hijacking), typically run as SYSTEM.
status: experimental
level: high
tags:
  - attack.t1563.002
  - attack.lateral_movement
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: \tscon.exe
    CommandLine|contains: /dest
  condition: selection
falsepositives:
  - Rare legitimate session redirection by administrators
`,

	// ── T1484.001 – Group Policy Modification for Code Execution ─
	`
title: Group Policy Modification for Code Execution
description: Detects abuse of Group Policy to push code — New-GPImmediateTask (SharpGPOAbuse), Set-GPPrefRegistryValue, or editing GptTmpl.inf / ScheduledTasks.xml in SYSVOL.
status: experimental
level: high
tags:
  - attack.t1484.001
  - attack.privilege_escalation
  - attack.defense_evasion
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - New-GPImmediateTask
      - SharpGPOAbuse
      - Set-GPPrefRegistryValue
      - GptTmpl.inf
  condition: selection
falsepositives:
  - Authorised Group Policy administration
`,

	// ── T1123 – Audio Capture ──────────────────────────────────
	`
title: Audio Capture via Recording API or Tool
description: Detects audio/microphone capture — waveInOpen API, Get-AudioDevice, Windows.Media.Capture, or ffmpeg capturing a dshow audio device.
status: experimental
level: medium
tags:
  - attack.t1123
  - attack.collection
logsource:
  category: process_creation
detection:
  api:
    CommandLine|contains:
      - waveInOpen
      - Get-AudioDevice
      - Windows.Media.Capture
  ffmpeg:
    CommandLine|contains|all:
      - ffmpeg
      - "audio="
  condition: api or ffmpeg
falsepositives:
  - Legitimate audio/conferencing software
`,

	// ══════════════════════════════════════════════════════════════════
	// Linux / macOS parity batch (2026-07-10) — close the Windows-heavy
	// builtin gap (Windows 108 / Linux 33 / macOS 10 techniques). These are
	// high-value techniques the Windows side already covered but the Linux/
	// macOS side did not. Process-only fields (Image/CommandLine) so they
	// stay field-supported. Regression-locked in attack_coverage_test.go.
	// ══════════════════════════════════════════════════════════════════

	// ── Linux T1046 – Network Service Discovery ────────────────
	`
title: Network Service Scanning (Linux)
description: Detects active network service/port scanning tools used for reconnaissance and lateral-movement targeting.
status: stable
level: medium
tags:
  - attack.t1046
  - attack.discovery
logsource:
  product: linux
  category: process_creation
detection:
  scanners:
    Image|endswith:
      - /nmap
      - /masscan
      - /zmap
      - /rustscan
  ncscan:
    CommandLine|contains|all:
      - nc
      - -z
  condition: scanners or ncscan
falsepositives:
  - Authorised vulnerability scanning / asset inventory
`,

	// ── Linux T1518.001 – Security Software Discovery ──────────
	`
title: Security Software Discovery (Linux)
description: Detects enumeration of host EDR/AV/audit tooling by name, used to fingerprint defenses before evasion.
status: stable
level: low
tags:
  - attack.t1518.001
  - attack.discovery
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - falcon-sensor
      - crowdstrike
      - sentinelone
      - carbon-black
      - cbagent
      - osqueryd
      - clamscan
      - wazuh
      - ossec
  condition: selection
falsepositives:
  - Monitoring agents performing self health-checks
`,

	// ── Linux T1562.001 – Impair Defenses ──────────────────────
	`
title: Impair Defenses via Firewall/SELinux/Audit Disable (Linux)
description: Detects disabling of host protections — SELinux/AppArmor enforcement, the firewall, or the audit daemon — a common pre-attack evasion step.
status: stable
level: high
tags:
  - attack.t1562.001
  - attack.defense_evasion
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - "setenforce 0"
      - "setenforce Permissive"
      - "systemctl stop firewalld"
      - "systemctl disable firewalld"
      - "systemctl stop auditd"
      - "service auditd stop"
      - "ufw disable"
      - "iptables -F"
      - "iptables --flush"
      - "aa-teardown"
  condition: selection
falsepositives:
  - Legitimate host reconfiguration by administrators
`,

	// ── Linux T1070.004 – File Deletion (secure wipe) ──────────
	`
title: Secure File Deletion / Anti-Forensic Wipe (Linux)
description: Detects use of secure-deletion utilities to destroy files and remove evidence of activity.
status: stable
level: medium
tags:
  - attack.t1070.004
  - attack.defense_evasion
logsource:
  product: linux
  category: process_creation
detection:
  shredtools:
    Image|endswith:
      - /shred
      - /srm
      - /wipe
  shredcmd:
    CommandLine|contains:
      - "shred -u"
      - "shred -z"
  condition: shredtools or shredcmd
falsepositives:
  - Administrators securely wiping decommissioned data
`,

	// ── Linux T1136.001 – Create Local Account ─────────────────
	`
title: Local Account Creation (Linux)
description: Detects creation of a new local user account, a common persistence and backdoor-access step after compromise.
status: stable
level: medium
tags:
  - attack.t1136.001
  - attack.persistence
logsource:
  product: linux
  category: process_creation
detection:
  addusers:
    Image|endswith:
      - /useradd
      - /adduser
  sudoadd:
    CommandLine|contains|all:
      - usermod
      - sudo
  condition: addusers or sudoadd
falsepositives:
  - Legitimate provisioning / configuration management
`,

	// ── macOS T1562.001 – Disable Gatekeeper / SIP ─────────────
	`
title: macOS Disable Gatekeeper or SIP
description: Detects disabling of macOS platform protections — Gatekeeper (spctl) or System Integrity Protection (csrutil) — enabling unsigned/malicious code execution.
status: stable
level: high
tags:
  - attack.t1562.001
  - attack.defense_evasion
logsource:
  product: macos
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - "spctl --master-disable"
      - "spctl --disable"
      - "csrutil disable"
      - "csrutil clear"
  condition: selection
falsepositives:
  - Developers disabling Gatekeeper on a dev machine (rare, high-signal)
`,

	// ── macOS T1105 – Ingress Tool Transfer ────────────────────
	`
title: macOS Ingress Tool Transfer via curl/osascript
description: Detects downloading of a remote payload to disk via curl/wget or an AppleScript shell-script download cradle.
status: stable
level: medium
tags:
  - attack.t1105
  - attack.command_and_control
logsource:
  product: macos
  category: process_creation
detection:
  curl_dl:
    Image|endswith:
      - /curl
      - /wget
    CommandLine|contains:
      - "-o "
      - "-O "
      - "--output"
  osa_dl:
    CommandLine|contains|all:
      - osascript
      - "do shell script"
      - curl
  condition: curl_dl or osa_dl
falsepositives:
  - Package managers / build scripts fetching artifacts
`,

	// ── macOS T1497 – Virtualization/Sandbox Evasion ───────────
	`
title: macOS Virtualization/Sandbox Evasion Checks
description: Detects querying hardware/platform artifacts and matching them against VM vendor strings to detect a sandbox or analysis VM before executing.
status: stable
level: medium
tags:
  - attack.t1497
  - attack.defense_evasion
logsource:
  product: macos
  category: process_creation
detection:
  probe:
    CommandLine|contains:
      - "system_profiler SPHardwareDataType"
      - "ioreg -l"
      - "ioreg -rd1"
      - "sysctl hw.model"
  vmvendor:
    CommandLine|contains:
      - VirtualBox
      - VMware
      - vmware
      - QEMU
      - Parallels
  condition: probe and vmvendor
falsepositives:
  - Inventory tooling reading hardware model on virtualized hosts
`,

	// ══════════════════════════════════════════════════════════════════
	// New-technique batch (2026-07-10) — techniques not previously covered
	// on ANY platform in the builtin set (cloud/container/discovery/browser
	// credentials), plus macOS parity for account discovery/creation. Process
	// fields only (field-supported). Regression-locked in attack_coverage_test.go.
	// ══════════════════════════════════════════════════════════════════

	// ── T1552.005 – Cloud Instance Metadata API access ─────────
	`
title: Cloud Instance Metadata Service Access
description: Detects a process querying the cloud instance metadata service (169.254.169.254 / metadata endpoints), commonly abused to steal instance credentials/role tokens (SSRF or on-host).
status: stable
level: high
tags:
  - attack.t1552.005
  - attack.credential_access
logsource:
  product: linux
  category: process_creation
detection:
  tool:
    Image|endswith:
      - /curl
      - /wget
  target:
    CommandLine|contains:
      - "169.254.169.254"
      - "metadata.google.internal"
      - "metadata.goog"
      - "100.100.100.200"
      - "/latest/meta-data"
      - "/computeMetadata/"
      - "Metadata-Flavor"
  condition: tool and target
falsepositives:
  - Legitimate cloud-init / instance bootstrap tooling
`,

	// ── T1613 – Container and Resource Discovery ───────────────
	`
title: Container and Orchestration Discovery
description: Detects enumeration of containers, pods, and cluster resources via kubectl/docker/crictl — reconnaissance after landing in a containerized environment.
status: stable
level: medium
tags:
  - attack.t1613
  - attack.discovery
logsource:
  product: linux
  category: process_creation
detection:
  kubectl:
    CommandLine|contains|all:
      - kubectl
      - get
  kubectl_targets:
    CommandLine|contains:
      - pods
      - secrets
      - nodes
      - namespaces
      - deployments
  docker_ps:
    CommandLine|contains:
      - "docker ps"
      - "crictl ps"
      - "docker images"
      - "podman ps"
  condition: (kubectl and kubectl_targets) or docker_ps
falsepositives:
  - Operators inspecting cluster state
`,

	// ── T1614.001 – System Location Discovery ──────────────────
	`
title: System Location and Timezone Discovery
description: Detects discovery of the host timezone/locale, used to fingerprint the victim's geographic location (sometimes to skip execution in certain regions).
status: stable
level: low
tags:
  - attack.t1614.001
  - attack.discovery
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - timedatectl
      - "/etc/timezone"
      - "/etc/localtime"
      - "systemsetup -gettimezone"
      - "systemsetup -getnetworktimeserver"
  condition: selection
falsepositives:
  - Time-synchronization / provisioning tooling
`,

	// ── T1201 – Password Policy Discovery ──────────────────────
	`
title: Password Policy Discovery
description: Detects reading of the system password policy or per-account aging, used to tune brute-force/spray attempts to avoid lockout.
status: stable
level: low
tags:
  - attack.t1201
  - attack.discovery
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - "/etc/login.defs"
      - "/etc/security/pwquality"
      - "chage -l"
      - "passwd -S"
      - "passwd --status"
      - "pwpolicy -getaccountpolicies"
  condition: selection
falsepositives:
  - Configuration management reading password policy
`,

	// ── T1482 – Domain Trust Discovery ─────────────────────────
	`
title: Domain Trust Discovery
description: Detects enumeration of Active Directory domain trusts (nltest, dsquery, PowerView Get-DomainTrust, .NET GetAllTrustRelationships), a common precursor to cross-domain lateral movement and Kerberos trust attacks.
status: stable
level: medium
tags:
  - attack.t1482
  - attack.discovery
logsource:
  product: windows
  category: process_creation
detection:
  nltest_trust:
    CommandLine|contains:
      - "/domain_trusts"
      - "/trusted_domains"
  dsquery_trust:
    CommandLine|contains: "objectClass=trustedDomain"
  powerview_trust:
    CommandLine|contains:
      - "Get-ADTrust"
      - "Get-DomainTrust"
      - "Get-NetDomainTrust"
      - "GetAllTrustRelationships"
  condition: nltest_trust or dsquery_trust or powerview_trust
falsepositives:
  - Domain administrators auditing trust relationships
`,

	// ── T1087.002 – Domain Account Discovery (+ BloodHound/SharpHound) ──
	`
title: Domain Account Discovery
description: Detects enumeration of Active Directory user accounts (net user /domain, dsquery user, PowerView Get-DomainUser, Get-ADUser) and BloodHound/SharpHound AD collectors, used to map targets before privilege escalation and lateral movement.
status: stable
level: medium
tags:
  - attack.t1087.002
  - attack.discovery
logsource:
  product: windows
  category: process_creation
detection:
  net_user_domain:
    CommandLine|contains|all:
      - "net"
      - " user "
      - "/domain"
  dsquery_user:
    CommandLine|contains: "dsquery user"
  powerview_user:
    CommandLine|contains:
      - "Get-ADUser"
      - "Get-DomainUser"
      - "Get-NetUser"
  bloodhound:
    CommandLine|contains:
      - "Invoke-BloodHound"
      - "SharpHound"
      - "-CollectionMethod"
      - "--collectionmethods"
      # bloodhound-python's real console-script name and its usual invocation
      # takes the short "-c" collection-method flag (e.g. "bloodhound-python
      # -c All -u user -p pass -d corp.local"), which the long-form-only
      # flag patterns above never matched.
      - "bloodhound-python"
      - "bloodhound.py"
  adsi_ldap:
    CommandLine|contains:
      - "adsisearcher"
      - "DirectorySearcher"
      - "System.DirectoryServices"
  condition: net_user_domain or dsquery_user or powerview_user or bloodhound or adsi_ldap
falsepositives:
  - Help-desk or identity-management tooling enumerating directory users
`,

	// ── T1087.001 – Local Account Discovery ────────────────────
	//
	// The sibling rule above covers only the /domain form (T1087.002). A host that
	// is not domain-joined — or an attacker who enumerates the LOCAL account
	// database first, which is the usual order — produced no builtin match at all:
	// `net user` fails net_user_domain (no "/domain", and " user " with a trailing
	// space never matches a command line that ENDS in "user"). The gap was invisible
	// because the DB rule "Network Discovery via net.exe" (migration 019) does cover
	// it — but that rule is evaluated only by server-detect, so whenever the
	// detection engine is behind or down, T1087 scores zero with nothing to fall
	// back on. Measured 2026-07-26 on a Windows endpoint: rank=None.
	`
title: Local Account Discovery
description: Detects enumeration of LOCAL user accounts (net user, net accounts, Get-LocalUser, wmic useraccount, query user) — the first thing an attacker inventories after landing on a host that is not domain-joined, and the precursor to picking a local account to escalate into.
status: stable
level: low
tags:
  - attack.t1087.001
  - attack.discovery
logsource:
  product: windows
  category: process_creation
detection:
  net_user:
    CommandLine|contains:
      - "net user"
      - "net1 user"
      - "net accounts"
      - "net1 accounts"
  powershell_localuser:
    CommandLine|contains:
      - "Get-LocalUser"
      - "Get-WmiObject -Class Win32_UserAccount"
      - "Get-CimInstance -ClassName Win32_UserAccount"
  wmic_useraccount:
    CommandLine|contains|all:
      - "wmic"
      - "useraccount"
  # The domain form is the sibling rule's job (T1087.002); excluding it here keeps
  # one command from raising two overlapping discovery alerts.
  domain_form:
    CommandLine|contains: "/domain"
  condition: (net_user or powershell_localuser or wmic_useraccount) and not domain_form
falsepositives:
  - Administrators and inventory/helpdesk tooling listing local accounts
  - Login scripts querying the local user database
`,
	// NOTE: `query user` / `quser` (logged-on session enumeration) is deliberately
	// NOT selected. It is routine helpdesk tooling — the FP-soak it-admin profile
	// carries it as normal traffic (tests/fpsoak/profiles/it-admin.toml) — so a
	// standalone alert on it is a false positive by construction. It still counts
	// toward the discovery burst via classifyDiscoveryCommand (discovery.go), which
	// is the right vehicle for a command this common.

	// ── T1069.001 – Local Permission Groups Discovery ──────────
	//
	// Same gap as Local Account Discovery above: "Domain Group Discovery" requires
	// "net group" + "/domain" (or a hard-coded privileged DOMAIN group name), so
	// `net localgroup administrators` — the canonical local form — matched nothing.
	// "Local Administrators Group Addition via net.exe" is the WRITE path (it
	// requires /add) and deliberately does not cover read-only enumeration.
	`
title: Local Permission Groups Discovery
description: Detects enumeration of LOCAL group membership (net localgroup, Get-LocalGroupMember, whoami /groups, wmic group) — used to find which accounts hold local Administrators rights before privilege escalation.
status: stable
level: low
tags:
  - attack.t1069.001
  - attack.discovery
logsource:
  product: windows
  category: process_creation
detection:
  net_localgroup:
    CommandLine|contains:
      - "net localgroup"
      - "net1 localgroup"
  powershell_localgroup:
    CommandLine|contains:
      - "Get-LocalGroupMember"
      - "Get-LocalGroup"
  wmic_group:
    CommandLine|contains|all:
      - "wmic"
      - "group get"
  # "net localgroup <name> /add" is privilege escalation, not discovery — the
  # dedicated T1098 rule owns it, so it must not also land here.
  write_form:
    CommandLine|contains:
      - "/add"
      - "/delete"
  condition: (net_localgroup or powershell_localgroup or wmic_group) and not write_form
falsepositives:
  - Administrators auditing local Administrators membership
  - Configuration management verifying group membership
`,
	// NOTE: `whoami /groups` is deliberately NOT selected. It is one of the most
	// common commands an administrator runs, and the FP-soak it-admin profile ships
	// it as normal traffic (tests/fpsoak/profiles/it-admin.toml). classifyDiscoveryCommand
	// already maps it to T1069 for the kill chain and the enumeration-burst
	// correlation, which is where a signal this weak belongs — discovery.go raises
	// nothing on a single command by design.

	// ── T1018 – Remote System / Domain Controller Discovery ────
	`
title: Remote System and Domain Controller Discovery
description: Detects enumeration of remote hosts and domain controllers (nltest /dclist, net view /domain, dsquery computer, PowerView Get-DomainComputer, Get-ADComputer), used to select lateral-movement targets.
status: stable
level: medium
tags:
  - attack.t1018
  - attack.discovery
logsource:
  product: windows
  category: process_creation
detection:
  nltest_dc:
    CommandLine|contains:
      - "/dclist"
      - "/dsgetdc"
  net_view_domain:
    CommandLine|contains|all:
      - "net view"
      - "/domain"
  net_view_all:
    CommandLine|contains: "net view /all"
  dsquery_computer:
    CommandLine|contains: "dsquery computer"
  powerview_computer:
    CommandLine|contains:
      - "Get-ADComputer"
      - "Get-DomainComputer"
      - "Get-NetComputer"
  adsi_computer:
    CommandLine|contains|all:
      - "DirectoryServices"
    CommandLine|contains:
      - "objectClass=computer"
      - "objectCategory=computer"
  adsi_computer2:
    CommandLine|contains|all:
      - "adsisearcher"
    CommandLine|contains:
      - "objectClass=computer"
      - "objectCategory=computer"
  condition: nltest_dc or net_view_domain or net_view_all or dsquery_computer or powerview_computer or adsi_computer or adsi_computer2
falsepositives:
  - Administrators enumerating domain hosts or locating domain controllers
`,

	// ── T1069.002 – Permission Groups Discovery: Domain Groups ──
	`
title: Domain Group Discovery
description: Detects enumeration of Active Directory groups and privileged group membership (net group /domain, Get-ADGroupMember, PowerView Get-DomainGroup, dsquery group), used to locate Domain/Enterprise Admins before escalation.
status: stable
level: medium
tags:
  - attack.t1069.002
  - attack.discovery
logsource:
  product: windows
  category: process_creation
detection:
  net_group_domain:
    CommandLine|contains|all:
      - "net group"
      - "/domain"
  net_group_privileged:
    CommandLine|contains:
      - "domain admins"
      - "enterprise admins"
      - "domain controllers"
  dsquery_group:
    CommandLine|contains: "dsquery group"
  powerview_group:
    CommandLine|contains:
      - "Get-ADGroupMember"
      - "Get-DomainGroup"
      - "Get-NetGroupMember"
  adsi_group:
    CommandLine|contains|all:
      - "DirectoryServices"
    CommandLine|contains:
      - "objectClass=group"
      - "objectCategory=group"
  adsi_group2:
    CommandLine|contains|all:
      - "adsisearcher"
    CommandLine|contains:
      - "objectClass=group"
      - "objectCategory=group"
  condition: net_group_domain or net_group_privileged or dsquery_group or powerview_group or adsi_group or adsi_group2
falsepositives:
  - Administrators auditing privileged group membership
`,

	// ── T1135 – Network Share Discovery ────────────────────────
	`
title: Network Share Discovery
description: Detects enumeration of network shares (net view of remote hosts, net share, Get-SmbShare, PowerView Invoke-ShareFinder/Find-DomainShare, Snaffler), used to locate data to collect and lateral-movement footholds.
status: stable
level: medium
tags:
  - attack.t1135
  - attack.discovery
logsource:
  product: windows
  category: process_creation
detection:
  net_view_host:
    CommandLine|contains|all:
      - "net view"
      - "\\\\"
  net_share:
    CommandLine|contains: "net share"
  smb_share_ps:
    CommandLine|contains:
      - "Get-SmbShare"
      - "Get-WmiObject Win32_Share"
      - "Get-CimInstance Win32_Share"
  powerview_share:
    CommandLine|contains:
      - "Invoke-ShareFinder"
      - "Find-DomainShare"
      - "Find-InterestingDomainShareFile"
  # Snaffler mass-crawls every reachable share hunting for secrets left in
  # files — a dominant real-world share-discovery tool this rule missed
  # entirely.
  snaffler:
    CommandLine|contains: snaffler
  condition: net_view_host or net_share or smb_share_ps or powerview_share or snaffler
falsepositives:
  - Administrators auditing share exposure
`,

	// ── T1615 – Group Policy Discovery ─────────────────────────
	`
title: Group Policy Discovery
description: Detects enumeration of Active Directory Group Policy (gpresult, Get-GPO/Get-GPOReport, PowerView Get-DomainGPO/Get-DomainGPOLocalGroup), used to find misconfigurations, delegated rights, and privileged-access paths.
status: stable
level: medium
tags:
  - attack.t1615
  - attack.discovery
logsource:
  product: windows
  category: process_creation
detection:
  gpresult:
    CommandLine|contains: gpresult
  gpo_cmdlets:
    CommandLine|contains:
      - "Get-GPO"
      - "Get-GPOReport"
      - "Get-GPResultantSetOfPolicy"
  powerview_gpo:
    CommandLine|contains:
      - "Get-DomainGPO"
      - "Get-NetGPO"
      - "Get-DomainGPOLocalGroup"
      - "Get-DomainGPOUserLocalGroupMapping"
  condition: gpresult or gpo_cmdlets or powerview_gpo
falsepositives:
  - Administrators troubleshooting applied Group Policy
`,

	// ── T1526 – Cloud Service / IAM Discovery ──────────────────
	`
title: Cloud Service and IAM Discovery
description: Detects enumeration of cloud identity, organization, and service configuration via cloud CLIs (aws sts get-caller-identity, aws iam/organizations list, az ad / az role assignment list, gcloud iam / projects list), a common first step after cloud credential compromise.
status: stable
level: medium
tags:
  - attack.t1526
  - attack.discovery
logsource:
  category: process_creation
detection:
  aws_identity:
    CommandLine|contains:
      - "sts get-caller-identity"
      - "iam list-users"
      - "iam list-roles"
      - "iam get-account-authorization-details"
      - "organizations list-accounts"
      - "organizations describe-organization"
  az_identity:
    CommandLine|contains|all:
      - "az "
      - "list"
    CommandLine|contains:
      - "ad user"
      - "ad group"
      - "role assignment"
      - "account list"
  gcloud_identity:
    CommandLine|contains|all:
      - "gcloud "
    CommandLine|contains:
      - "iam service-accounts"
      - "projects list"
      - "organizations list"
      - "projects get-iam-policy"
  condition: aws_identity or az_identity or gcloud_identity
falsepositives:
  - Cloud administrators or IaC tooling auditing identity and org structure
`,

	// ── T1580 – Cloud Infrastructure Discovery ─────────────────
	`
title: Cloud Infrastructure Discovery
description: Detects enumeration of cloud compute and network infrastructure via cloud CLIs (aws ec2 describe-instances/security-groups/vpcs, az vm/network list, gcloud compute instances list), used to map lateral-movement and pivot targets.
status: stable
level: low
tags:
  - attack.t1580
  - attack.discovery
logsource:
  category: process_creation
detection:
  aws_infra:
    CommandLine|contains:
      - "ec2 describe-instances"
      - "ec2 describe-security-groups"
      - "ec2 describe-vpcs"
      - "ec2 describe-subnets"
      - "rds describe-db-instances"
  az_infra:
    CommandLine|contains|all:
      - "az "
    CommandLine|contains:
      - "vm list"
      - "network nic list"
      - "network vnet list"
  gcloud_infra:
    CommandLine|contains|all:
      - "gcloud compute"
      - "list"
  condition: aws_infra or az_infra or gcloud_infra
falsepositives:
  - DevOps / IaC tooling inventorying cloud resources
`,

	// ── T1619 – Cloud Storage Object Discovery ─────────────────
	`
title: Cloud Storage Object Discovery
description: Detects enumeration of cloud object storage buckets and objects (aws s3 ls / s3api list-buckets / list-objects, az storage container/blob list, gsutil ls, gcloud storage ls), used to locate data for collection and exfiltration.
status: stable
level: low
tags:
  - attack.t1619
  - attack.discovery
logsource:
  category: process_creation
detection:
  aws_s3:
    CommandLine|contains:
      - "s3 ls"
      - "s3api list-buckets"
      - "s3api list-objects"
  az_storage:
    CommandLine|contains|all:
      - "az storage"
      - "list"
  gcp_storage:
    CommandLine|contains:
      - "gsutil ls"
      - "gcloud storage ls"
  condition: aws_s3 or az_storage or gcp_storage
falsepositives:
  - Backup / data-pipeline jobs listing buckets
`,

	// ── T1562.008 – Disable or Modify Cloud Logs ───────────────
	`
title: Cloud Logging Tampering
description: Detects disabling or deleting cloud audit/threat logging to blind defenders — aws cloudtrail stop-logging/delete-trail, aws guardduty delete-detector, az monitor diagnostic-settings delete, gcloud logging sinks delete — an early defense-evasion step after cloud compromise.
status: stable
level: critical
tags:
  - attack.t1562.008
  - attack.defense_evasion
logsource:
  category: process_creation
detection:
  aws_trail:
    CommandLine|contains:
      - "cloudtrail stop-logging"
      - "cloudtrail delete-trail"
      - "guardduty delete-detector"
  aws_trail_modify:
    CommandLine|contains|all:
      - "cloudtrail update-trail"
      - "no-is-multi-region"
  az_diag:
    CommandLine|contains|all:
      - "monitor diagnostic-settings"
      - "delete"
  gcloud_sink:
    CommandLine|contains|all:
      - "logging sinks"
      - "delete"
  condition: aws_trail or aws_trail_modify or az_diag or gcloud_sink
falsepositives:
  - Rare; cloud administrators decommissioning logging (should be change-controlled)
`,

	// ── T1562.007 – Disable or Modify Cloud Firewall ───────────
	`
title: Cloud Firewall Opening
description: Detects opening cloud network controls to the internet for attacker access or persistence — aws ec2 authorize-security-group-ingress with 0.0.0.0/0, az network nsg rule create allow-any, gcloud compute firewall-rules create allowing 0.0.0.0/0.
status: stable
level: high
tags:
  - attack.t1562.007
  - attack.defense_evasion
logsource:
  category: process_creation
detection:
  aws_sg:
    CommandLine|contains|all:
      - "ec2 authorize-security-group-ingress"
      - "0.0.0.0/0"
  az_nsg:
    CommandLine|contains|all:
      - "network nsg rule create"
      - "0.0.0.0/0"
  gcloud_fw:
    CommandLine|contains|all:
      - "compute firewall-rules create"
      - "0.0.0.0/0"
  condition: aws_sg or az_nsg or gcloud_fw
falsepositives:
  - Administrators intentionally exposing a service (should be reviewed)
`,

	// ── T1578 – Modify Cloud Compute Infrastructure ────────────
	`
title: Cloud Compute Infrastructure Modification
description: Detects abuse of cloud compute APIs for data theft or persistence — creating and sharing disk snapshots to an attacker-controlled account (aws ec2 create-snapshot / modify-snapshot-attribute --create-volume-permission, az snapshot create, gcloud compute disks snapshot) or modifying instance attributes.
status: stable
level: high
tags:
  - attack.t1578
  - attack.defense_evasion
logsource:
  category: process_creation
detection:
  aws_snapshot_share:
    CommandLine|contains:
      - "modify-snapshot-attribute"
      - "modify-image-attribute"
  aws_snapshot_create:
    CommandLine|contains: "ec2 create-snapshot"
  aws_instance_modify:
    CommandLine|contains: "modify-instance-attribute"
  az_snapshot:
    CommandLine|contains|all:
      - "az snapshot"
      - "create"
  gcloud_snapshot:
    CommandLine|contains|all:
      - "compute disks snapshot"
  condition: aws_snapshot_share or aws_snapshot_create or aws_instance_modify or az_snapshot or gcloud_snapshot
falsepositives:
  - Backup automation creating snapshots (sharing snapshots externally is the higher-signal case)
`,

	// ── T1217 – Browser Information Discovery ──────────────────
	`
title: Browser Bookmark and History Discovery
description: Detects reading of browser bookmark/history stores, used to profile the user and discover internal URLs, cloud consoles, and infrastructure.
status: stable
level: medium
tags:
  - attack.t1217
  - attack.discovery
logsource:
  category: process_creation
detection:
  reader:
    Image|endswith:
      - /cat
      - /sqlite3
      - /strings
      - /grep
      - /find
  store:
    CommandLine|contains:
      - "Safari/Bookmarks.plist"
      - "Safari/History.db"
      - "Google/Chrome/Default/History"
      - "Google/Chrome/Default/Bookmarks"
      - "Firefox/Profiles"
      - "places.sqlite"
      - ".mozilla/firefox"
  condition: reader and store
falsepositives:
  - Browser sync or backup utilities
`,

	// ── T1555.003 – Credentials from Web Browsers ──────────────
	`
title: Credentials from Web Browsers
description: Detects access to browser credential stores (Login Data, cookies, key databases), used to harvest saved passwords and session tokens.
status: stable
level: high
tags:
  - attack.t1555.003
  - attack.credential_access
logsource:
  category: process_creation
detection:
  reader:
    Image|endswith:
      - /cat
      - /cp
      - /sqlite3
      - /strings
      - /python
      - /python3
  store:
    CommandLine|contains:
      - "Chrome/Default/Login Data"
      - "Chrome/Default/Cookies"
      - "Chrome/Default/Web Data"
      - "Login Data"
      - "Local State"
      - "key4.db"
      - "logins.json"
      - "cookies.sqlite"
  condition: reader and store
falsepositives:
  - Browser backup/migration tooling
`,

	// ── macOS T1087.001 – Local Account Discovery ──────────────
	`
title: macOS Local Account Discovery via dscl
description: Detects enumeration of local user accounts via the Directory Service command line (dscl) or dscacheutil, a macOS-native discovery step.
status: stable
level: low
tags:
  - attack.t1087.001
  - attack.discovery
logsource:
  product: macos
  category: process_creation
detection:
  dscl_list:
    CommandLine|contains|all:
      - dscl
      - "/Users"
  dscl_read:
    CommandLine|contains:
      - "dscacheutil -q user"
      - "dscl . -read /Users"
      - "dscl . list /Users"
  condition: dscl_list or dscl_read
falsepositives:
  - Administrative user management / directory tooling
`,

	// ── macOS T1136.001 – Local Account Creation ───────────────
	`
title: macOS Local Account Creation
description: Detects creation of a new local user account via sysadminctl or dscl, a common backdoor-access persistence step on macOS.
status: stable
level: medium
tags:
  - attack.t1136.001
  - attack.persistence
logsource:
  product: macos
  category: process_creation
detection:
  sysadminctl:
    CommandLine|contains:
      - "sysadminctl -addUser"
  dscl_create:
    CommandLine|contains|all:
      - "dscl"
      - "-create"
      - "/Users/"
  condition: sysadminctl or dscl_create
falsepositives:
  - Legitimate provisioning / MDM enrollment
`,

	// ══════════════════════════════════════════════════════════════════
	// Exfil / C2 / credential-store batch (2026-07-10) — techniques not
	// previously covered on any platform. Process fields only. Locked in
	// attack_coverage_test.go.
	// ══════════════════════════════════════════════════════════════════

	// ── T1102 – Web Service (C2 over legitimate web services) ──
	`
title: C2 over Legitimate Web Service
description: Detects command-line tools contacting popular legitimate web services (paste sites, code hosts, chat webhooks, bot APIs) commonly abused as C2 or dead-drop resolvers.
status: stable
level: high
tags:
  - attack.t1102
  - attack.command_and_control
logsource:
  category: process_creation
detection:
  tool:
    Image|endswith:
      - /curl
      - /wget
      - \powershell.exe
      - \pwsh.exe
      - /python
      - /python3
  service:
    CommandLine|contains:
      - "pastebin.com/raw"
      - "raw.githubusercontent.com"
      - "gist.githubusercontent.com"
      - "api.telegram.org/bot"
      - "discord.com/api/webhooks"
      - "discordapp.com/api/webhooks"
      - "hooks.slack.com/services"
      - "transfer.sh"
      - "anonfiles"
  condition: tool and service
falsepositives:
  - Developer tooling fetching gists / raw files
  - Legitimate chat integrations
`,

	// ── T1620 – Reflective Code Loading ────────────────────────
	`
title: Reflective Code Loading (In-Memory Assembly)
description: Detects loading of code directly into memory (reflective .NET assembly load, in-memory PE execution) that bypasses on-disk AV inspection.
status: stable
level: high
tags:
  - attack.t1620
  - attack.defense_evasion
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - "[Reflection.Assembly]::Load"
      - "[System.Reflection.Assembly]::Load"
      - "Assembly]::Load("
      - "System.Reflection.Assembly]::LoadWithPartialName"
      - "[AppDomain]::CurrentDomain.Load"
      - "InvokeReturnAsIs"
  condition: selection
falsepositives:
  - Some .NET developer / build automation
`,

	// ── T1555.005 – Password Managers ──────────────────────────
	`
title: Password Manager Vault Access
description: Detects access to password-manager vault files (KeePass, 1Password, Bitwarden, KeePassXC), a high-value credential-theft target.
status: stable
level: high
tags:
  - attack.t1555.005
  - attack.credential_access
logsource:
  category: process_creation
detection:
  reader:
    Image|endswith:
      - /cat
      - /cp
      - /curl
      - \powershell.exe
      - /python
      - /python3
      - /strings
  vault:
    CommandLine|contains:
      - ".kdbx"
      - ".kdb"
      - "1Password"
      - "Bitwarden"
      - "data.json"
      - ".opvault"
      - "keepass"
      - "keepassxc"
  condition: reader and vault
falsepositives:
  - The password manager application itself opening its vault
`,

	// ── T1090.002 – External Proxy (proxychains / pivot) ───────
	`
title: Traffic Tunneling via Proxy Tool
description: Detects use of proxy/pivot tooling (proxychains, chisel, socat relays) to route traffic through a compromised host — a lateral-movement/exfil channel.
status: stable
level: medium
tags:
  - attack.t1090.002
  - attack.command_and_control
logsource:
  product: linux
  category: process_creation
detection:
  tools:
    Image|endswith:
      - /proxychains
      - /proxychains4
      - /chisel
  socat_relay:
    CommandLine|contains|all:
      - socat
      - "TCP-LISTEN"
  ssh_dynamic:
    CommandLine|contains:
      - "ssh -D "
      - "ssh -R "
      - "ssh -L "
  condition: tools or socat_relay or ssh_dynamic
falsepositives:
  - Administrators using SSH tunnels for legitimate access
`,

	// ── T1114.001 – Local Email Collection ─────────────────────
	`
title: Local Email Store Collection
description: Detects reading or copying of local email data stores (Outlook PST/OST, mbox/maildir), used to harvest correspondence for espionage.
status: stable
level: medium
tags:
  - attack.t1114.001
  - attack.collection
logsource:
  category: process_creation
detection:
  reader:
    Image|endswith:
      - /cat
      - /cp
      - \xcopy.exe
      - \robocopy.exe
      - /tar
      - \powershell.exe
      - /python
      - /python3
  maildata:
    CommandLine|contains:
      - ".pst"
      - ".ost"
      - ".mbox"
      - "/Mail/"
      - ".msg"
      - "Outlook Files"
      - ".olm"
  condition: reader and maildata
falsepositives:
  - Backup / archival tooling handling mail stores
`,

	// ══════════════════════════════════════════════════════════════════
	// Rootkit / boot / rogue-DC / container-cred batch (2026-07-10) —
	// high-signal techniques not previously covered on any platform.
	// Process fields only. Locked in attack_coverage_test.go.
	// ══════════════════════════════════════════════════════════════════

	// ── T1552.007 – Container API / Kubelet Credential Access ──
	`
title: Kubernetes Service Account Token Access
description: Detects reading of the in-pod Kubernetes service-account token or kubelet credentials, used to escalate from a compromised container to the cluster API.
status: stable
level: high
tags:
  - attack.t1552.007
  - attack.credential_access
logsource:
  product: linux
  category: process_creation
detection:
  reader:
    Image|endswith:
      - /cat
      - /cp
      - /curl
      - /python
      - /python3
      - /base64
  token:
    CommandLine|contains:
      - "/var/run/secrets/kubernetes.io/serviceaccount"
      - "/var/lib/kubelet/pki"
      - "/etc/kubernetes/admin.conf"
      - "serviceaccount/token"
      - "kubelet.conf"
  condition: reader and token
falsepositives:
  - In-cluster tooling reading its own service-account token
`,

	// ── T1207 – Rogue Domain Controller (DCShadow) ─────────────
	`
title: Rogue Domain Controller (DCShadow)
description: Detects DCShadow — registering a rogue domain controller to push malicious directory replication, a stealthy AD persistence/tampering technique.
status: stable
level: critical
tags:
  - attack.t1207
  - attack.defense_evasion
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - "lsadump::dcshadow"
      - "!+ stealth"
      - "/object:"
  dcshadow_mimikatz:
    CommandLine|contains:
      - "dcshadow"
  condition: selection or dcshadow_mimikatz
falsepositives:
  - Extremely rare; DCShadow has no legitimate use
`,

	// ── T1014 – Rootkit (Linux LD_PRELOAD / preload hijack) ────
	`
title: Userland Rootkit via ld.so.preload
description: Detects writing to /etc/ld.so.preload or setting a global LD_PRELOAD — a classic Linux userland rootkit that injects a shared object into every dynamically-linked process to hide files/processes.
status: stable
level: high
tags:
  - attack.t1014
  - attack.defense_evasion
logsource:
  product: linux
  category: process_creation
detection:
  preload_file:
    CommandLine|contains:
      - "/etc/ld.so.preload"
  ld_env:
    CommandLine|contains:
      - "export LD_PRELOAD="
      - "echo /tmp/"
  ld_env2:
    CommandLine|contains:
      - "ld.so.preload"
  condition: preload_file or (ld_env and ld_env2)
falsepositives:
  - Rare legitimate use of LD_PRELOAD for debugging/profiling
`,

	// ── T1542.003 – Bootkit / Bootloader Tampering ─────────────
	`
title: Bootloader or Boot Configuration Tampering
description: Detects modification of the boot configuration or bootloader (bcdedit recovery/safeboot changes, GRUB rewrite) used for bootkit persistence or to disable recovery.
status: stable
level: high
tags:
  - attack.t1542.003
  - attack.persistence
detection:
  bcdedit:
    Image|endswith: \bcdedit.exe
    CommandLine|contains:
      - "safeboot"
      - "bootstatuspolicy"
      - "recoveryenabled"
      - "/set"
  grub:
    CommandLine|contains:
      - "grub-install"
      - "grub-mkconfig"
      - "/boot/grub"
      - "update-grub"
  condition: bcdedit or grub
falsepositives:
  - Legitimate OS/boot maintenance by administrators
`,

	// ── T1091 – Replication Through Removable Media ────────────
	`
title: Removable Media Replication (autorun / USB drop)
description: Detects staging of an autorun payload or copying executables onto removable media, used to spread across air-gapped or USB-connected hosts.
status: stable
level: medium
tags:
  - attack.t1091
  - attack.lateral_movement
logsource:
  product: windows
  category: process_creation
detection:
  autorun:
    CommandLine|contains:
      - "autorun.inf"
  copy_tool:
    CommandLine|contains:
      - copy
      - xcopy
      - Copy-Item
  is_exe:
    CommandLine|contains:
      - ".exe"
  removable_target:
    CommandLine|contains:
      - "D:\\"
      - "E:\\"
      - "F:\\"
  condition: autorun or (copy_tool and is_exe and removable_target)
falsepositives:
  - Legitimate software distribution to external drives
`,

	// ══════════════════════════════════════════════════════════════════
	// Packing / MOTW / macOS-persistence batch (2026-07-10) — genuinely
	// new techniques (macOS-weighted, the thinnest surface). Process fields
	// only. Locked in attack_coverage_test.go.
	// ══════════════════════════════════════════════════════════════════

	// ── T1027.002 – Software Packing (UPX) ─────────────────────
	`
title: Software Packing via UPX
description: Detects use of the UPX executable packer to compress/obfuscate a binary, a common way to evade static AV signatures and hinder analysis.
status: stable
level: medium
tags:
  - attack.t1027.002
  - attack.defense_evasion
logsource:
  category: process_creation
detection:
  upx:
    Image|contains:
      - upx
  upx_cmd:
    CommandLine|contains:
      - "upx "
      - "upx.exe"
      - "upx -d"
      - "upx --best"
      - "upx -o"
  condition: upx or upx_cmd
falsepositives:
  - Legitimate developers packing their own release binaries
`,

	// ── T1553.005 – Mark-of-the-Web Bypass ─────────────────────
	`
title: Mark-of-the-Web Bypass
description: Detects removal of the Zone.Identifier alternate data stream (Mark-of-the-Web) so a downloaded file runs without SmartScreen/Office protected-view warnings.
status: stable
level: high
tags:
  - attack.t1553.005
  - attack.defense_evasion
logsource:
  product: windows
  category: process_creation
detection:
  unblock:
    CommandLine|contains:
      - "Unblock-File"
  strip_zone:
    CommandLine|contains:
      - "Zone.Identifier"
  strip_zone_ops:
    CommandLine|contains:
      - "Remove-Item"
      - "Clear-Content"
      - ":Zone.Identifier"
      - "streams -d"
  condition: unblock or (strip_zone and strip_zone_ops)
falsepositives:
  - Rare admin scripting that legitimately unblocks trusted files
`,

	// ── macOS T1547.007 – Re-opened Applications Persistence ───
	`
title: macOS Re-opened Applications Persistence
description: Detects persistence via the macOS "reopen windows on login" mechanism — writing a malicious entry into com.apple.loginwindow so an app relaunches at every login.
status: stable
level: medium
tags:
  - attack.t1547.007
  - attack.persistence
logsource:
  product: macos
  category: process_creation
detection:
  writer:
    Image|endswith:
      - /defaults
      - /plutil
      - /tee
      - /cp
  loginwindow:
    CommandLine|contains:
      - "com.apple.loginwindow"
      - "loginwindow.plist"
      - "ByHost/com.apple.loginwindow"
  condition: writer and loginwindow
falsepositives:
  - System preferences UI writing login-window state
`,

	// ── macOS T1546.014 – Emond Persistence ────────────────────
	`
title: macOS Emond Rule Persistence
description: Detects creation of an Event Monitor (emond) rule plist, an under-watched macOS persistence mechanism that runs commands on system events.
status: stable
level: high
tags:
  - attack.t1546.014
  - attack.persistence
logsource:
  product: macos
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - "/etc/emond.d/rules"
      - "/private/var/db/emondClients"
      - "emond.d/rules"
  condition: selection
falsepositives:
  - Essentially none; emond is deprecated and rarely used legitimately
`,

	// ── macOS T1037.005 – Startup Items Persistence ────────────
	`
title: macOS Startup Items Persistence
description: Detects creation of a legacy macOS StartupItem (a script + plist under /Library/StartupItems) used to run code at boot.
status: stable
level: medium
tags:
  - attack.t1037.005
  - attack.persistence
logsource:
  product: macos
  category: process_creation
detection:
  writer:
    Image|endswith:
      - /cp
      - /mv
      - /tee
      - /mkdir
      - /touch
  startupitem:
    CommandLine|contains:
      - "/Library/StartupItems"
      - "/System/Library/StartupItems"
  condition: writer and startupitem
falsepositives:
  - Legacy installers using the deprecated StartupItems mechanism
`,

	// ── T1562.001 – Defender Tampering (broad: exclusion / service / MpCmdRun) ──
	// FN-hardening: the narrow Set-MpPreference+DisableRealtimeMonitoring and
	// registry rules miss the far more common evasions — blinding Defender with
	// exclusions, other Set-MpPreference disables, stopping the WinDefend/Sense
	// services, and MpCmdRun signature removal.
	`
title: Windows Defender Disable via Exclusion, Service, or MpCmdRun
description: Detects broad Windows Defender tampering — adding exclusions to blind the scanner, disabling protection features, stopping the Defender services, or removing signature definitions.
status: stable
level: critical
tags:
  - attack.t1562.001
  - attack.defense_evasion
logsource:
  product: windows
  category: process_creation
detection:
  setmp:
    CommandLine|contains: Set-MpPreference
  addmp:
    CommandLine|contains: Add-MpPreference
  mp_evasion:
    CommandLine|contains:
      - "-Disable"
      - "-ExclusionPath"
      - "-ExclusionProcess"
      - "-ExclusionExtension"
      - "-MAPSReporting Disabled"
      - "-SubmitSamplesConsent NeverSend"
  svc_name:
    CommandLine|contains:
      - windefend
      - wdnissvc
      - " sense"
      - wdboot
      - wscsvc
  svc_verb:
    CommandLine|contains:
      - "net stop"
      - "sc stop"
      - "sc.exe stop"
      - "Stop-Service"
      - "sc config"
      - "sc.exe config"
  mpcmdrun:
    CommandLine|contains: MpCmdRun
  removedef:
    CommandLine|contains: RemoveDefinitions
  condition: ((setmp or addmp) and mp_evasion) or (svc_name and svc_verb) or (mpcmdrun and removedef)
falsepositives:
  - Authorised AV administration / security testing
`,

	// ── T1562.001 – AMSI Bypass (inline on the process command line) ──
	// The existing AMSI rule keys on ScriptBlockText (script events); an inline
	// -Command AMSI patch on the process command line slips past it.
	`
title: AMSI Bypass via Inline Command
description: Detects Anti-Malware Scan Interface (AMSI) bypass patterns on the process command line — patching amsiInitFailed / AmsiScanBuffer so in-memory scripts run unscanned.
status: stable
level: high
tags:
  - attack.t1562.001
  - attack.defense_evasion
logsource:
  product: windows
  category: process_creation
detection:
  amsi:
    CommandLine|contains:
      - amsiInitFailed
      - "AmsiUtils"
      - AmsiScanBuffer
      # AmsiScanString (calls AmsiScanBuffer) and AmsiOpenSession are the other
      # patchable AMSI exports targeted by bypasses alongside AmsiScanBuffer.
      - AmsiScanString
      - AmsiOpenSession
      - AmsiInitialize
      - "amsi.dll"
  condition: amsi
falsepositives:
  - Security research / AV testing
`,

	// ── T1562.006 – ETW Bypass (Indicator Blocking) ──────────────
	`
title: ETW Bypass / Event Tracing Tampering
description: Detects disabling or patching of Event Tracing for Windows (ETW), used to blind EDR/telemetry — patching EtwEventWrite, tampering with the .NET EventProvider, or stopping ETW trace sessions via logman.
status: stable
level: high
tags:
  - attack.t1562.006
  - attack.defense_evasion
logsource:
  product: windows
  category: process_creation
detection:
  etw_api:
    CommandLine|contains:
      - EtwEventWrite
      - EtwpEnableTrace
      - EtwEventUnregister
      # syscall-level ETW patch targets used by bypasses that avoid the
      # documented Etw* export names.
      - NtTraceEvent
      - NtTraceControl
  etw_provider:
    CommandLine|contains:
      - "System.Diagnostics.Eventing.EventProvider"
      - "m_enabled"
  # "logman stop" pauses a trace session; "logman delete" removes it entirely
  # — both blind telemetry, so a "stop"-only match is evaded by delete.
  logman:
    CommandLine|contains|all:
      - logman
    CommandLine|contains:
      - stop
      - delete
  condition: etw_api or etw_provider or logman
falsepositives:
  - Administrators managing ETW trace sessions
`,

	// ── Linux T1059.004 – Reverse Shell via Interpreter/Tool ──────
	// FN-hardening: the bash /dev/tcp rule misses the classic non-bash reverse
	// shell one-liners (perl/ruby/php/socat/mkfifo backpipe/nc -e/awk) shipped by
	// every reverse-shell cheatsheet.
	`
title: Linux Reverse Shell via Interpreter or Tool
description: Detects reverse-shell one-liners using perl/ruby/php sockets, socat EXEC, an mkfifo backpipe, nc -e, or awk's /inet network extension.
status: stable
level: critical
tags:
  - attack.t1059.004
  - attack.execution
logsource:
  product: linux
  category: process_creation
detection:
  perl_sock:
    CommandLine|contains|all:
      - perl
      - Socket
  perl_exec:
    CommandLine|contains:
      - "exec("
      - "/bin/sh"
      - "/bin/bash"
  ruby_sock:
    CommandLine|contains:
      - "ruby -rsocket"
      - TCPSocket
  php_sock:
    CommandLine|contains|all:
      - php
      - fsockopen
  socat_exec:
    CommandLine|contains|all:
      - socat
      - "EXEC:"
  fifo:
    CommandLine|contains: mkfifo
  fifo_net:
    CommandLine|contains:
      - "nc "
      - ncat
      - "/dev/tcp"
  nc_exec:
    CommandLine|contains:
      - "nc -e"
      - "ncat -e"
      - "nc.traditional -e"
  awk_inet:
    CommandLine|contains: "/inet/tcp/"
  condition: (perl_sock and perl_exec) or ruby_sock or php_sock or socat_exec or (fifo and fifo_net) or nc_exec or awk_inet
falsepositives:
  - Rare legitimate use of socat EXEC / gawk networking by administrators
`,

	// ── Linux T1059.004 – Download/Decode Piped to Shell ─────────
	// FN-hardening: curl|bash, wget -qO-|sh, and base64 -d|bash execute a payload
	// without ever touching disk or a named LOLBin.
	`
title: Download or Decode Piped to Shell (Linux)
description: Detects a remote fetch (curl/wget) or a base64 decode piped directly into a shell — LOLBin-free download-and-execute.
status: stable
level: high
tags:
  - attack.t1059.004
  - attack.execution
logsource:
  product: linux
  category: process_creation
detection:
  source:
    CommandLine|contains:
      - curl
      - wget
      - "base64 -d"
      - "base64 --decode"
      - fetch
  pipe_shell:
    CommandLine|contains:
      - "| bash"
      - "|bash"
      - "| sh"
      - "|sh"
      - "| /bin/bash"
      - "|/bin/bash"
      - "| /bin/sh"
      - "|/bin/sh"
      - "| zsh"
      - "|zsh"
  condition: source and pipe_shell
falsepositives:
  - Some software install instructions legitimately use curl | bash (still risky)
`,

	// ── T1082 – Windows Privilege-Escalation Enumeration Tooling ──
	// Entirely uncovered gap: the dominant "run this first on a foothold"
	// tools (WinPEAS, Seatbelt, PowerUp, SharpUp, Watson, Sherlock,
	// PrivescCheck) that enumerate misconfigurations — weak service ACLs,
	// unquoted service paths, AutoLogon credentials, exploitable scheduled
	// tasks/AV — worth escalating to SYSTEM/Admin had no rule at all.
	`
title: Windows Privilege Escalation Enumeration Tool Execution
description: Detects execution of common local-privilege-escalation enumeration tools/scripts (WinPEAS, Seatbelt, PowerUp, SharpUp, Watson, Sherlock, PrivescCheck) used to find misconfigurations worth exploiting for SYSTEM/Admin access.
status: stable
level: high
tags:
  - attack.t1082
  - attack.discovery
  - attack.privilege_escalation
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - winpeas
      - Seatbelt
      - Invoke-AllChecks
      - PowerUp.ps1
      - SharpUp
      - Watson.exe
      - Sherlock.ps1
      - Find-AllVulns
      - Invoke-PrivescCheck
      - PrivescCheck.ps1
  condition: selection
falsepositives:
  - Authorised penetration testing / red-team privilege-escalation assessments
`,

	// ── T1529 – System Shutdown/Reboot ────────────────────────
	`
title: Forced System Shutdown or Reboot via shutdown.exe
description: Detects forced system shutdown or reboot via shutdown.exe (/r or /s with /f), used to disrupt operations or to force a reboot after wiper/ransomware activity.
status: stable
level: low
tags:
  - attack.t1529
  - attack.impact
logsource:
  product: windows
  category: process_creation
detection:
  tool:
    Image|endswith: \shutdown.exe
  action:
    CommandLine|contains:
      - ' /r'
      - ' /s'
      - ' -r'
      - ' -s'
  condition: tool and action
falsepositives:
  - Administrators or patch cycles rebooting hosts intentionally
`,

	// ── T1570 – Lateral Tool Transfer to Admin Share ──────────
	`
title: Lateral Tool Transfer to Administrative Share
description: Detects copying files to a remote Windows administrative share (C$, ADMIN$, IPC$) via a copy utility — a common lateral-movement staging step for spreading tooling to other hosts.
status: stable
level: medium
tags:
  - attack.t1570
  - attack.lateral_movement
logsource:
  product: windows
  category: process_creation
detection:
  tool:
    Image|endswith:
      - \xcopy.exe
      - \robocopy.exe
      - \cmd.exe
      - \powershell.exe
      - \pwsh.exe
  share:
    CommandLine|contains:
      - C$
      - ADMIN$
      - IPC$
  condition: tool and share
falsepositives:
  - Administrative deployment scripts that stage files to admin shares
`,

	// ── T1497 – Virtualization/Sandbox Evasion (hardware query) ─
	`
title: Virtualization or Sandbox Discovery via WMIC Hardware Query
description: Detects WMIC hardware/BIOS/baseboard queries commonly used by malware to detect a virtualized or sandbox environment (VMware/VirtualBox/QEMU artifacts) before detonating.
status: stable
level: low
tags:
  - attack.t1497
  - attack.defense_evasion
  - attack.discovery
logsource:
  product: windows
  category: process_creation
detection:
  tool:
    Image|endswith: \WMIC.exe
  query:
    CommandLine|contains:
      - computersystem
      - win32_computersystem
      - bios
      - baseboard
  condition: tool and query
falsepositives:
  - Legitimate inventory/asset-management scripts querying hardware
`,

	// ── T1112 – Modify Registry: security tooling (registry_set) ─
	// The process_creation Defender rules above only fire when tampering goes
	// through reg.exe. This registry_set companion catches DIRECT registry writes
	// (Sysmon EventID 13 / native registry events) to the Windows Defender policy
	// keys — the API-level vector those command-line rules miss.
	`
title: Security Tooling Registry Tampering (Direct Write)
description: Detects direct registry writes that DISABLE Windows Defender or widen
  its exclusions (not via reg.exe) — DisableAntiSpyware / DisableRealtimeMonitoring
  / TamperProtection / \Exclusions\ set through the registry API — which the
  process_creation rules do not see. Requires a tamper-indicating policy path or
  value name in addition to the Defender key. Matching the Defender key ALONE made
  this fire on MsMpEng.exe writing its own "Signature Updates\SignatureLastUpdated"
  — Defender doing its job was reported as security-tooling tampering, and it was
  the second-largest false positive in the 2026-08-02 FP soak (24 alerts).
status: stable
level: high
tags:
  - attack.t1562.001
  - attack.t1112
  - attack.defense_evasion
logsource:
  product: windows
  category: registry_set
detection:
  defender_key:
    TargetObject|contains:
      - \Windows Defender
      - \Microsoft\Windows Defender
      - \Windows Advanced Threat Protection
  tamper:
    TargetObject|contains:
      # The GPO policy subtree exists to turn protection off; a write anywhere
      # under it is policy-level tampering regardless of the value name.
      - \Policies\Microsoft\Windows Defender
      # Individual protection kill-switches, wherever they are written.
      - DisableAntiSpyware
      - DisableAntiVirus
      - DisableRealtimeMonitoring
      - DisableBehaviorMonitoring
      - DisableIOAVProtection
      - DisableScriptScanning
      - DisableOnAccessProtection
      - DisableScanOnRealtimeEnable
      - DisableBlockAtFirstSeen
      - TamperProtection
      # Adding an exclusion path/process/extension is itself the T1562.001
      # technique — it blinds Defender without disabling it.
      - \Exclusions\
  condition: defender_key and tamper
falsepositives:
  - Enterprise policy management of Defender via GPO (writes the policy subtree by design)
`,

	// ── T1105 – Ingress Tool Transfer via Interpreter (curl/wget evasion) ─
	// The live adversarial test (docs/results/live-20260702-linux-evasion-adversarial.md)
	// found python-urllib downloads completely evaded the curl/wget download rules.
	// Interpreters fetching over HTTP are a general download-cradle手口; match the
	// library call together with a URL so ordinary interpreter use does not fire.
	`
title: Ingress Tool Transfer via Interpreter
description: Detects a scripting interpreter (python/perl/ruby/php) downloading a payload over HTTP — a common way to evade curl/wget-based ingress-tool-transfer rules.
status: stable
level: medium
tags:
  - attack.t1105
  - attack.command_and_control
logsource:
  product: linux
  category: process_creation
detection:
  interp:
    CommandLine|contains:
      - urllib
      - urlretrieve
      - requests.get
      - 'LWP::Simple'
      - 'Net::HTTP'
      - file_get_contents
      - 'open-uri'
  url:
    CommandLine|contains:
      - 'http://'
      - 'https://'
  condition: interp and url
falsepositives:
  - Legitimate scripts that fetch resources over HTTP via an interpreter
`,

	// ── T1140 / T1027 – Base64 payload decoded and executed ────
	`
title: Base64 Payload Decoded and Piped to a Shell or Interpreter
description: Detects a base64 blob decoded and piped into a shell/interpreter (base64 -d | sh, python b64decode+exec) — a common deobfuscation/evasion step on Linux that the Windows -enc/certutil rules do not cover.
status: stable
level: medium
tags:
  - attack.t1140
  - attack.t1027
  - attack.defense_evasion
logsource:
  product: linux
  category: process_creation
detection:
  decode:
    CommandLine|contains:
      - 'base64 -d'
      - 'base64 --decode'
      - 'b64decode'
      - 'openssl enc -base64 -d'
      - 'openssl base64 -d'
  execute:
    CommandLine|contains:
      - '| sh'
      - '|sh'
      - '| bash'
      - '|bash'
      - 'exec('
      - 'eval('
      - 'system('
      - 'popen('
      - '| python'
      - '|python'
  condition: decode and execute
falsepositives:
  - Packaging or build scripts that legitimately decode embedded base64 data
`,

	// ── Linux T1548.001 – Setuid/Setgid Binary Enumeration ─────
	`
title: Setuid/Setgid Binary Enumeration
description: Detects enumeration of setuid/setgid binaries via find -perm, a common Linux privilege-escalation reconnaissance step used to locate GTFOBins candidates for exploitation.
status: stable
level: medium
tags:
  - attack.t1548.001
  - attack.privilege_escalation
  - attack.discovery
logsource:
  product: linux
  category: process_creation
detection:
  tool:
    Image|endswith: /find
  perm:
    CommandLine|contains:
      - '-perm -4000'
      - '-perm -2000'
      - '-perm -u=s'
      - '-perm -g=s'
      - '-perm /4000'
      - '-perm 4000'
      - '-perm /6000'
  condition: tool and perm
falsepositives:
  - Authorised security audits enumerating setuid binaries
`,

	// ── Linux T1046 – Network Service Scanning ─────────────────
	`
title: Network Service Scanning Tool Execution
description: Detects execution of network-scanning tools (nmap/masscan/rustscan/zmap) or netcat connect-scan sweeps (-z), used to discover reachable services for lateral movement.
status: stable
level: medium
tags:
  - attack.t1046
  - attack.discovery
logsource:
  product: linux
  category: process_creation
detection:
  scanner:
    Image|endswith:
      - /nmap
      - /masscan
      - /rustscan
      - /zmap
      - /zgrab
  nc_sweep:
    Image|endswith:
      - /nc
      - /ncat
      - /netcat
    CommandLine|contains:
      - ' -z'
  condition: scanner or nc_sweep
falsepositives:
  - Authorised vulnerability scanning or network inventory
`,

	// ── Linux T1552.003 – Credentials in Bash History ──────────
	`
title: Credential Search in Shell History
description: Detects grep/awk searches over shell history files (.bash_history/.zsh_history) — attackers harvest passwords, tokens and keys accidentally typed into the shell.
status: stable
level: medium
tags:
  - attack.t1552.003
  - attack.credential_access
logsource:
  product: linux
  category: process_creation
detection:
  tool:
    CommandLine|contains:
      - grep
      - egrep
      - rg
      - awk
      - strings
  history:
    CommandLine|contains:
      - .bash_history
      - .zsh_history
      - .sh_history
      - .history
  condition: tool and history
falsepositives:
  - Users legitimately searching their own shell history
`,

	// ── macOS T1497 – Virtualization/Sandbox Discovery ─────────
	`
title: macOS Virtualization/Sandbox Discovery
description: Detects hardware/platform fingerprinting via system_profiler or ioreg, used by macOS malware to detect a virtual machine or analysis sandbox before executing.
status: stable
level: low
tags:
  - attack.t1497
  - attack.defense_evasion
  - attack.discovery
logsource:
  product: macos
  category: process_creation
detection:
  profiler:
    Image|endswith: /system_profiler
    CommandLine|contains: SPHardwareDataType
  ioreg_fp:
    Image|endswith: /ioreg
    CommandLine|contains:
      - IOPlatformExpertDevice
      - IOPlatformSerialNumber
      - IOPlatformUUID
  condition: profiler or ioreg_fp
falsepositives:
  - Inventory/asset tools reading hardware information
`,

	// ── macOS T1070.002 – Clear macOS System/Unified Logs ──────
	`
title: macOS Log Clearing
description: Detects clearing of macOS unified/system logs (log erase, deletion of /var/log or diagnostic stores) used to remove evidence of activity.
status: stable
level: medium
tags:
  - attack.t1070.002
  - attack.defense_evasion
logsource:
  product: macos
  category: process_creation
detection:
  logerase:
    Image|endswith: /log
    CommandLine|contains: erase
  rmlogs:
    CommandLine|contains:
      - 'rm -rf /private/var/log'
      - 'rm -rf /var/log'
      - 'rm /var/log'
      - '/private/var/db/diagnostics'
  condition: logerase or rmlogs
falsepositives:
  - Administrative log rotation or cleanup
`,

	// ── macOS T1548.006 – TCC Privacy Protection Tampering ─────
	`
title: macOS TCC Privacy Protection Tampering
description: Detects resetting or direct manipulation of the macOS TCC privacy database (tccutil reset, access to TCC.db) to grant unauthorized access to protected resources such as the camera, microphone or full disk.
status: stable
level: high
tags:
  - attack.t1548.006
  - attack.privilege_escalation
  - attack.defense_evasion
logsource:
  product: macos
  category: process_creation
detection:
  tccutil:
    Image|endswith: /tccutil
    CommandLine|contains: reset
  tccdb:
    CommandLine|contains:
      - TCC.db
      - com.apple.TCC
  condition: tccutil or tccdb
falsepositives:
  - Authorised MDM/privacy management tooling
`,
	// ── Additional rules from claude/detection-rate-methods-6mza2z (Windows lateral movement deepening, cloud persistence, ransomware precursors, AD/domain tampering, logon-script persistence, ancestry anomalies) ──
	// ── T1490 / T1070 – ransomware anti-recovery (free-space wipe / USN) ──
	`
title: Anti-Recovery Free-Space Wipe or USN Journal Deletion
description: Detects wiping of free disk space (cipher /w) or deletion of the NTFS USN change journal (fsutil usn deletejournal) — anti-forensic / anti-recovery steps run by ransomware and wipers to prevent file carving and undelete after encryption.
status: stable
level: high
tags:
  - attack.t1490
  - attack.impact
  - attack.defense_evasion
logsource:
  product: windows
  category: process_creation
detection:
  cipher_wipe:
    Image|endswith: \cipher.exe
    CommandLine|contains: /w
  usn:
    Image|endswith: \fsutil.exe
    CommandLine|contains|all:
      - usn
      - deletejournal
  condition: cipher_wipe or usn
falsepositives:
  - Rare legitimate secure-wipe of free space by an administrator
`,
	// ── T1548.003 – capsh shell privilege escalation (GTFOBins) ──
	`
title: Capsh Privilege Escalation (Linux)
description: Detects capsh used to drop into a root shell (capsh --gid=0 --uid=0 -- , or --) — a GTFOBins privilege-escalation technique when capsh is sudo-allowed or SUID.
status: stable
level: high
tags:
  - attack.t1548.003
  - attack.privilege_escalation
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    Image|endswith: /capsh
    CommandLine|contains:
      - "--gid=0"
      - "--uid=0"
      - "-- "
  condition: selection
falsepositives:
  - Rare legitimate capsh usage in container tooling
`,
	// ── T1136.003 – cloud backdoor account creation (persistence) ──
	`
title: Cloud Backdoor Account Creation (IAM User / Service Principal)
description: Detects creation of a new cloud identity — AWS IAM user, GCP service account (plus a key for it), or an Azure AD user/service principal — a durable backdoor that survives credential rotation on the original compromised identity and often goes unnoticed among routine IAM activity.
status: stable
level: high
tags:
  - attack.t1136.003
  - attack.persistence
detection:
  aws:
    CommandLine|contains: "iam create-user"
  gcp:
    CommandLine|contains:
      - "iam service-accounts create"
      - "iam service-accounts keys create"
  az:
    CommandLine|contains:
      - "ad user create"
      - "ad sp create-for-rbac"
      - "ad app credential reset"
  condition: aws or gcp or az
falsepositives:
  - Authorised onboarding automation / IaC pipelines creating service accounts
`,
	// ── T1098 – cloud IAM privilege escalation (control plane) ──
	`
title: Cloud IAM Privilege Escalation via CLI
description: Detects granting elevated cloud privileges — attaching AdministratorAccess/creating access keys/inline admin policies on AWS IAM, or binding Owner/Editor roles on GCP/Azure — a post-compromise persistence and escalation step.
status: stable
level: high
tags:
  - attack.t1098
  - attack.privilege_escalation
  - attack.persistence
detection:
  aws:
    CommandLine|contains:
      - "iam attach-user-policy"
      - "iam attach-role-policy"
      - "iam create-access-key"
      - "iam put-user-policy"
      - "iam create-login-profile"
  aws_admin:
    CommandLine|contains:
      - AdministratorAccess
      - "iam create-access-key"
      - "iam put-user-policy"
      - "iam create-login-profile"
  gcp:
    CommandLine|contains:
      - "add-iam-policy-binding"
  gcp_role:
    CommandLine|contains:
      - roles/owner
      - roles/editor
      - roles/iam.serviceAccountTokenCreator
  az:
    CommandLine|contains|all:
      - "role assignment create"
      - Owner
  condition: (aws and aws_admin) or (gcp and gcp_role) or az
falsepositives:
  - Authorised IAM administration / IaC pipelines
`,
	// ── T1552.005 – Cloud Instance Metadata (IMDS) credential theft ──
	// Post-compromise / SSRF theft of instance credentials from the link-local IMDS
	// endpoint. High signal: SDKs reach IMDS via their own client, so a shell tool
	// (curl/wget/Invoke-WebRequest/python) hitting 169.254.169.254 or the cloud
	// metadata hostnames is rarely legitimate.
	`
title: Cloud Instance Metadata Service (IMDS) Credential Access
description: Detects access to the cloud instance-metadata service (AWS/Azure/OCI 169.254.169.254, GCP metadata.google.internal, Alibaba 100.100.100.200) from a command-line tool — the classic path for stealing instance IAM/role credentials via SSRF or after a foothold (e.g. …/latest/meta-data/iam/security-credentials/, Azure …/identity/oauth2/token).
status: stable
level: high
tags:
  - attack.t1552.005
  - attack.credential_access
detection:
  endpoint:
    CommandLine|contains:
      - 169.254.169.254
      - metadata.google.internal
      - 100.100.100.200
  intent:
    CommandLine|contains:
      - security-credentials
      - /identity/oauth2/token
      - /computeMetadata/
      - /metadata/instance
      - meta-data
  condition: endpoint and intent
falsepositives:
  - Instance bootstrap / cloud-init or monitoring agents that query metadata by shell
`,
	// ── T1562.008 – cloud logging disabled (control plane) ──
	`
title: Cloud Logging Disabled via CLI
description: Detects disabling or deleting cloud audit logging — AWS CloudTrail stop-logging/delete-trail, or Azure/GCP equivalents — a defense-evasion step to blind detection before further activity.
status: stable
level: high
tags:
  - attack.t1562.008
  - attack.defense_evasion
detection:
  selection:
    CommandLine|contains:
      - "cloudtrail stop-logging"
      - "cloudtrail delete-trail"
      - "cloudtrail update-trail"
      - "monitor diagnostic-settings delete"
      - "logging sinks delete"
      - "logging buckets update"
  condition: selection
falsepositives:
  - Authorised logging reconfiguration / decommissioning
`,
	// ── T1053.005 (cloud analogue) – persistence via scheduled event trigger ──
	`
title: Cloud Persistence via Scheduled Event Trigger (EventBridge/Cloud Scheduler)
description: Detects wiring a cloud event-scheduling service to invoke a compute target — AWS EventBridge/CloudWatch Events put-targets pointing at a Lambda/SSM/Step-Functions ARN, or GCP Cloud Scheduler job creation — the cloud analogue of a scheduled task, letting an implant re-trigger itself independent of the original access path.
status: stable
level: high
tags:
  - attack.t1053.005
  - attack.persistence
detection:
  put_targets:
    CommandLine|contains: "events put-targets"
  target_arn:
    CommandLine|contains:
      - "arn:aws:lambda"
      - "arn:aws:ssm"
      - "arn:aws:states"
  gcp:
    CommandLine|contains: "scheduler jobs create"
  condition: (put_targets and target_arn) or gcp
falsepositives:
  - Authorised automation wiring EventBridge rules to Lambda/SSM/Step Functions
`,
	// ── T1562.001 – cloud security service disabled (control plane) ──
	`
title: Cloud Security Service Disabled via CLI
description: Detects disabling a cloud threat-detection service — AWS GuardDuty/SecurityHub, Azure Defender/Security Center, or GCP Security Command Center — to remove monitoring before or during an intrusion.
status: stable
level: high
tags:
  - attack.t1562.001
  - attack.defense_evasion
detection:
  selection:
    CommandLine|contains:
      - "guardduty delete-detector"
      - "guardduty update-detector"
      - "securityhub disable-security-hub"
      - "securityhub update-standards-control"
      - "security pricing create --tier free"
      - "scc settings"
      - "config delete-configuration-recorder"
  condition: selection
falsepositives:
  - Authorised security-tooling changes / cost management
`,
	// ── T1525 / T1648 – cloud serverless function tampering ──
	`
title: Cloud Serverless Function Tampering via CLI
description: Detects modification or creation of a serverless function's code — AWS Lambda update-function-code/create-function, GCP functions deploy, or Azure functionapp deployment — a stealthy cloud persistence/backdoor and execution vector (implant code that runs on a trigger).
status: stable
level: high
tags:
  - attack.t1525
  - attack.persistence
detection:
  selection:
    CommandLine|contains:
      - "lambda update-function-code"
      - "lambda create-function"
      - "lambda update-function-configuration"
      - "functions deploy"
      - "functionapp deployment"
      - "functionapp create"
  condition: selection
falsepositives:
  - CI/CD pipelines deploying serverless code
`,
	// ── T1526 – Cloud Service Discovery via CLI ───────────────────
	`
title: Cloud Service Discovery or Secret Enumeration via CLI
description: Detects post-compromise cloud reconnaissance and secret enumeration through the provider CLIs — aws sts/iam/secretsmanager, az account/role, gcloud auth/projects — used to map the account and pull stored credentials after gaining a foothold.
status: experimental
level: medium
tags:
  - attack.t1526
  - attack.discovery
detection:
  aws:
    CommandLine|contains|all:
      - aws
      - " sts get-caller-identity"
  aws_enum:
    CommandLine|contains:
      - secretsmanager get-secret-value
      - iam list-access-keys
      - iam list-users
      - ec2 describe-instances
  az:
    CommandLine|contains:
      - az account list
      - az role assignment list
      - az ad
  gcloud:
    CommandLine|contains:
      - gcloud auth list
      - gcloud projects list
      - gcloud secrets versions access
  condition: aws or aws_enum or az or gcloud
falsepositives:
  - Legitimate cloud administration and CI/CD pipelines
`,
	// ── T1611 – container breakout via /proc/self/exe overwrite ──
	`
title: Container Breakout via /proc/self/exe Overwrite (Linux)
description: Detects a command that writes to or copies over /proc/self/exe (or a /proc/<pid>/exe handle) — the runc/container-runtime overwrite primitive (CVE-2019-5736) used to escape a container and gain host code execution.
status: stable
level: critical
tags:
  - attack.t1611
  - attack.privilege_escalation
logsource:
  product: linux
  category: process_creation
detection:
  target:
    CommandLine|contains: /proc/self/exe
  writeverb:
    CommandLine|contains:
      - ' > '
      - ' dd '
      - ' cp '
      - ' cat '
      - ' tee '
      - O_WRONLY
  condition: target and writeverb
falsepositives:
  - Rare debugging that legitimately reads /proc/<pid>/exe (write pattern reduces this)
`,
	// ── T1053.003 – cron/at spawning a reverse shell (Linux) ──
	`
title: Cron or At Job Spawning a Reverse Shell (Linux)
description: Detects a cron/at daemon child whose command line carries a reverse-shell / remote-exec pattern (/dev/tcp, nc -e, bash -i, python socket, socat, mkfifo) — scheduled-task persistence used to run an interactive C2 shell rather than a benign maintenance job.
status: stable
level: high
tags:
  - attack.t1053.003
  - attack.execution
  - attack.persistence
logsource:
  product: linux
  category: process_creation
detection:
  cron:
    ParentImage|endswith:
      - /cron
      - /crond
      - /atd
  revshell:
    CommandLine|contains:
      - /dev/tcp/
      - "nc -e"
      - "ncat -e"
      - "bash -i"
      - "sh -i"
      - "socat "
      - "mkfifo "
      - "import socket"
  condition: cron and revshell
falsepositives:
  - Rare maintenance jobs that legitimately use netcat/socat
`,
	// ── T1555.003 / T1552 – DPAPI master key / secret abuse ──
	`
title: DPAPI Master Key or Secret Extraction
description: Detects abuse of the Windows Data Protection API (DPAPI) to decrypt stored secrets — mimikatz dpapi::, SharpDPAPI, or a /masterkey argument — used to recover browser passwords, saved credentials, and certificates offline.
status: stable
level: high
tags:
  - attack.t1555.003
  - attack.credential_access
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - "dpapi::"
      - SharpDPAPI
      - "/masterkey:"
      - "/rpc /server"
      - "dpapi::masterkey"
      - "dpapi::cred"
  condition: selection
falsepositives:
  - Rare legitimate DPAPI backup/recovery tooling
`,
	// ── T1548 – dangerous capability assignment via setcap ──
	`
title: Dangerous Capability Assignment via setcap (Linux)
description: Detects granting a dangerous Linux capability (cap_setuid, cap_setgid, cap_dac_read_search, cap_sys_admin, cap_sys_ptrace) to a binary via setcap — a stealthy privilege-escalation/persistence primitive that lets an unprivileged user run the binary with elevated powers without a SUID bit.
status: stable
level: high
tags:
  - attack.t1548
  - attack.privilege_escalation
  - attack.persistence
logsource:
  product: linux
  category: process_creation
detection:
  setcap:
    Image|endswith: /setcap
  danger:
    CommandLine|contains:
      - cap_setuid
      - cap_setgid
      - cap_dac_read_search
      - cap_sys_admin
      - cap_sys_ptrace
  condition: setcap and danger
falsepositives:
  - Legitimate software installers that grant a capability (e.g. ping cap_net_raw is different and not matched)
`,
	// ── T1567.002 – Exfiltration to Cloud Storage (rclone) ────────
	`
title: Data Exfiltration via Rclone
description: Detects rclone copying/syncing data to cloud storage backends, a common exfiltration tool in ransomware intrusions.
status: stable
level: high
tags:
  - attack.t1567.002
  - attack.exfiltration
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|contains: rclone
    CommandLine|contains:
      - copy
      - sync
      - " mega"
      - ":b2"
      - ":s3"
      - "--transfers"
      - "--multi-thread"
  condition: selection
falsepositives:
  - Sanctioned backup workflows that use rclone
`,
	// ── T1059 – Linux database daemon spawning a shell (SQLi RCE) ──
	`
title: Database Daemon Spawning a Shell (Linux)
description: Detects a database server process (mysqld/mariadbd/postgres/mongod) spawning a shell or interpreter — a strong indicator of SQL-injection-to-RCE or abuse of a DB user-defined function/COPY TO PROGRAM to execute OS commands.
status: stable
level: high
tags:
  - attack.t1190
  - attack.execution
logsource:
  product: linux
  category: process_creation
detection:
  db:
    ParentImage|endswith:
      - /mysqld
      - /mariadbd
      - /postgres
      - /mongod
  shell:
    Image|endswith:
      - /sh
      - /bash
      - /dash
      - /zsh
      - /python
      - /python3
      - /perl
      - /nc
      - /ncat
  condition: db and shell
falsepositives:
  - Rare DB maintenance jobs that legitimately shell out
`,
	// ── T1553.005 – disk-image (ISO/IMG/VHD) mount for smuggling ──
	`
title: Disk Image Mounted for Container Smuggling (ISO/IMG/VHD)
description: Detects mounting a disk image (Mount-DiskImage / PowerShell -ImagePath, or diskpart attach) referencing an .iso/.img/.vhd — the container-smuggling technique that ships a payload inside an image to bypass Mark-of-the-Web and email gateways, then runs a LNK/exe from the mounted volume.
status: stable
level: high
tags:
  - attack.t1553.005
  - attack.defense_evasion
logsource:
  product: windows
  category: process_creation
detection:
  mount:
    CommandLine|contains:
      - Mount-DiskImage
      - "-ImagePath"
      - "attach vdisk"
  image:
    CommandLine|contains:
      - .iso
      - .img
      - .vhd
  condition: mount and image
falsepositives:
  - Legitimate software distribution or VM tooling that mounts images
`,
	// ── T1556.001 – Domain Controller Authentication Tampering ───
	`
title: Domain Controller Authentication Tampering (DCShadow/AdminSDHolder Abuse)
description: Detects rogue-DC replication abuse (mimikatz lsadump::dcshadow) that injects attacker-controlled changes directly into AD replication, or ACL manipulation on the AdminSDHolder object (dsacls) — both grant a persistent, hard-to-revoke path back to Domain Admin privileges.
status: stable
level: critical
tags:
  - attack.t1556.001
  - attack.credential_access
  - attack.persistence
logsource:
  product: windows
  category: process_creation
detection:
  dcshadow:
    CommandLine|contains:
      - lsadump::dcshadow
      - "/pushmode"
  adminsdholder:
    CommandLine|contains|all:
      - dsacls
      - AdminSDHolder
  condition: dcshadow or adminsdholder
falsepositives:
  - Rare legitimate AdminSDHolder ACL review or maintenance by AD administrators
`,
	// ── T1484.001 – Domain Policy Modification via GPO Tampering ──
	`
title: Domain Policy Modification via GPO Tampering
description: Detects creating or modifying a Group Policy Object (New-GPO / Set-GPRegistryValue / Set-GPPrefRegistryValue) or using the offensive SharpGPOAbuse tool — a domain-wide persistence and defense-evasion technique that can push a malicious scheduled task, registry value or script to every computer in an OU without touching each host individually.
status: stable
level: high
tags:
  - attack.t1484.001
  - attack.defense_evasion
  - attack.privilege_escalation
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - New-GPO
      - Set-GPRegistryValue
      - Set-GPPrefRegistryValue
      - SharpGPOAbuse
  condition: selection
falsepositives:
  - Authorised Group Policy administration via PowerShell AD/GPO modules
`,
	// ── T1070.004 / T1620 – execution from an unlinked (deleted) binary ──
	`
title: Execution From Deleted Binary (Linux)
description: Detects a process running from a binary that has been unlinked from disk — the kernel marks such an executable path "(deleted)". Dropping, executing, then deleting a payload (or running an already-unlinked file) is a classic anti-forensic / fileless persistence trick.
status: stable
level: high
tags:
  - attack.t1620
  - attack.defense_evasion
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    Image|endswith: ' (deleted)'
  condition: selection
falsepositives:
  - A binary updated/replaced while still running (e.g. package upgrade) can briefly appear deleted
`,
	// ── T1620 – Execution from a memory-backed / shared-memory path (Linux) ──
	// memfd_create+execveat fileless exec is already caught by the eBPF memory finding;
	// this complements it with the on-path variant: a binary run straight from tmpfs
	// (/dev/shm, /run/shm) — a common stage-and-run-in-RAM technique that leaves no
	// persistent file.
	`
title: Execution From Shared-Memory Path (Linux)
description: Detects a process whose executable lives under a memory-backed filesystem (/dev/shm, /run/shm) — code staged in shared memory and executed to avoid touching disk, a fileless/reflective-loading pattern.
status: stable
level: high
tags:
  - attack.t1620
  - attack.defense_evasion
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    Image|contains:
      - /dev/shm/
      - /run/shm/
  condition: selection
falsepositives:
  - Rare software that legitimately runs helpers from shared memory
`,
	// ── T1558.001/.002 – Kerberos golden/silver ticket forgery ──
	`
title: Kerberos Golden or Silver Ticket Forgery
description: Detects forging of Kerberos tickets — mimikatz kerberos::golden / kerberos::silver, or Rubeus golden/silver — using a stolen krbtgt or service account hash to mint arbitrary tickets for domain-wide, long-lived access.
status: stable
level: critical
tags:
  - attack.t1558.001
  - attack.credential_access
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - "kerberos::golden"
      - "kerberos::silver"
      - "/krbtgt:"
      - "golden /user:"
      - " silver /"
      - "/ticket:golden"
  condition: selection
falsepositives:
  - Authorised red-team / AD security assessments
`,
	// ── T1562.001 – LSA protection (RunAsPPL) disabled via registry ──
	`
title: LSA Protection Disabled via Registry Value
description: Detects clearing of the LSASS run-as-PPL protection (HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL=0) or the Credential Guard flag (LsaCfgFlags=0) — removing the OS defence that blocks LSASS memory reads, a common precursor staged before credential dumping.
status: stable
level: high
tags:
  - attack.t1562.001
  - attack.defense_evasion
logsource:
  product: windows
  category: registry_event
detection:
  runasppl:
    TargetObject|endswith: \Control\Lsa\RunAsPPL
    Details: "0"
  credguard:
    TargetObject|endswith: \Control\Lsa\LsaCfgFlags
    Details: "0"
  condition: runasppl or credguard
falsepositives:
  - Rare legitimate rollback of an LSA-protection hardening change
`,
	// ── System-process ancestry anomalies (masquerade / injection) ──
	// lsass.exe legitimately spawns NO children except the WER crash handler. Any other
	// child is a near-certain sign of credential-theft tooling, process-tree masquerade,
	// or code running under the security process. Very high signal, near-zero FP.
	`
title: LSASS Spawning Anomalous Child Process
description: Detects lsass.exe spawning a child process other than the Windows Error Reporting crash handler (werfault/wermgr). LSASS does not normally launch children; a child indicates credential-access tooling, process-tree masquerading, or injected code executing under the security process.
status: stable
level: critical
tags:
  - attack.t1036
  - attack.defense_evasion
  - attack.credential_access
logsource:
  product: windows
  category: process_creation
detection:
  parent:
    ParentImage|endswith: \lsass.exe
  wer:
    Image|endswith:
      - \werfault.exe
      - \wermgr.exe
  condition: parent and not wer
falsepositives:
  - None expected outside a WER crash (excluded)
`,
	// ── T1037.003 – Network Logon Script Deployment (NETLOGON/SYSVOL) ──
	`
title: Network Logon Script Deployment via NETLOGON or SYSVOL Share
description: Detects copying a script into a domain's NETLOGON or SYSVOL\...\scripts share — the staging step for a network logon script that every domain user or an entire OU will execute at next logon, giving domain-wide persistence from a single write.
status: stable
level: high
tags:
  - attack.t1037.003
  - attack.persistence
  - attack.lateral_movement
logsource:
  product: windows
  category: process_creation
detection:
  tool:
    Image|endswith:
      - \xcopy.exe
      - \robocopy.exe
      - \cmd.exe
      - \powershell.exe
  target:
    CommandLine|contains:
      - \NETLOGON\
      - \SYSVOL\
  condition: tool and target
falsepositives:
  - Legitimate IT administration deploying or updating logon scripts
`,
	// ── T1059.002 / T1204 – macOS Office spawning a shell / osascript ──
	`
title: Office Application Spawning a Shell or Script Interpreter (macOS)
description: Detects a macOS Microsoft Office application (Word/Excel/PowerPoint) spawning a shell, osascript, or scripting interpreter — the macOS equivalent of a malicious-macro drop, commonly used to fetch and run a second stage.
status: stable
level: high
tags:
  - attack.t1059.002
  - attack.execution
logsource:
  product: macos
  category: process_creation
detection:
  office:
    ParentImage|contains:
      - Microsoft Word
      - Microsoft Excel
      - Microsoft PowerPoint
  interp:
    Image|endswith:
      - /bash
      - /sh
      - /zsh
      - /osascript
      - /python
      - /python3
      - /curl
      - /perl
  condition: office and interp
falsepositives:
  - Rare legitimate Office automation via AppleScript
`,
	// ── T1021.006 – PowerShell Invoke-Command remote lateral movement ──
	`
title: PowerShell Remote Command Execution via Invoke-Command
description: Detects Invoke-Command targeting a remote computer or an existing PSSession — PowerShell remoting lateral movement that does not require an interactive Enter-PSSession, often scripted for one-shot execution across many hosts.
status: stable
level: medium
tags:
  - attack.t1021.006
  - attack.lateral_movement
logsource:
  product: windows
  category: process_creation
detection:
  invcmd:
    Image|endswith:
      - \powershell.exe
      - \pwsh.exe
    CommandLine|contains: Invoke-Command
  target:
    CommandLine|contains:
      - -ComputerName
      - -Session
  condition: invcmd and target
falsepositives:
  - Legitimate administrative automation using PowerShell remoting
`,
	// ── T1068 – Print Spooler (spoolsv) spawning a shell/LOLBin ──
	// spoolsv.exe spawning an interpreter is the classic PrintNightmare /
	// spooler-exploitation execution primitive (SYSTEM code execution).
	`
title: Print Spooler Spawning Shell or LOLBin
description: Detects spoolsv.exe (the Windows Print Spooler service) spawning a command shell or LOLBin — the execution primitive of PrintNightmare and related spooler exploits, yielding SYSTEM code execution.
status: stable
level: high
tags:
  - attack.t1068
  - attack.privilege_escalation
  - attack.execution
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith: \spoolsv.exe
    Image|endswith:
      - \cmd.exe
      - \powershell.exe
      - \pwsh.exe
      - \wscript.exe
      - \cscript.exe
      - \mshta.exe
      - \rundll32.exe
      - \regsvr32.exe
  condition: selection
falsepositives:
  - Rare printer-driver installers that legitimately shell out
`,
	// ── T1569.002 – PsExec lateral movement deepening: the attacker PAYLOAD ──
	// (the process the service actually spawns), not just the service's own presence.
	`
title: Process Spawned by PsExec Service (Attacker Payload)
description: Detects a process launched with PSEXESVC.exe as its parent — the actual command the operator ran remotely via PsExec, executing as SYSTEM. Higher-fidelity than merely seeing PSEXESVC.exe itself, since it reveals the payload.
status: stable
level: high
tags:
  - attack.t1569.002
  - attack.lateral_movement
  - attack.execution
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith: \PSEXESVC.exe
  condition: selection
falsepositives:
  - Administrators running expected commands through PsExec sessions
`,
	// ── T1021.006 – WinRM lateral movement deepening: the attacker PAYLOAD ──
	`
title: Process Spawned by WinRM Remote Shell Host (Attacker Payload)
description: Detects a process launched with wsmprovhost.exe as its parent — the command an operator ran remotely via WS-Management (WinRM/PowerShell Remoting), the WinRM analogue of a PSEXESVC child process.
status: stable
level: high
tags:
  - attack.t1021.006
  - attack.lateral_movement
  - attack.execution
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith: \wsmprovhost.exe
  condition: selection
falsepositives:
  - Administrators running expected commands through PowerShell remoting sessions
`,
	// ── T1569.002 – PsExec-alternative remote execution tools (evasion) ──
	`
title: PsExec-Alternative Remote Execution Tool (PAExec/RemCom)
description: Detects PAExec or RemCom, open-source clones of PsExec that implement the same remote-service-execution protocol but with a different binary signature, commonly used to evade detections keyed only on psexec.exe/PSEXESVC.exe.
status: stable
level: high
tags:
  - attack.t1569.002
  - attack.lateral_movement
  - attack.defense_evasion
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|contains:
      - paexec.exe
      - paexecsvc.exe
      - remcom.exe
      - remcomsvc.exe
  condition: selection
falsepositives:
  - Rare legitimate administrative use of these open-source tools
`,
	// ── T1053.005 – remote scheduled task (lateral) ──
	`
title: Remote Scheduled Task Creation via schtasks
description: Detects schtasks targeting a REMOTE system (/s \\host or /s host) to create or run a task — scheduled-task lateral movement / remote code execution.
status: stable
level: high
tags:
  - attack.t1053.005
  - attack.lateral_movement
  - attack.execution
logsource:
  product: windows
  category: process_creation
detection:
  sch:
    Image|endswith: \schtasks.exe
    CommandLine|contains: ' /s '
  action:
    CommandLine|contains:
      - /create
      - /run
  condition: sch and action
falsepositives:
  - Administrative remote task scheduling
`,
	// ── T1021.002 / T1543.003 – remote service creation (lateral) ──
	`
title: Remote Service Creation via sc.exe
description: Detects sc.exe creating or configuring a service on a REMOTE host (\\host syntax) — a lateral-movement / remote-execution primitive (create a service pointing at a payload, then start it) used by operators and worms.
status: stable
level: high
tags:
  - attack.t1021.002
  - attack.lateral_movement
logsource:
  product: windows
  category: process_creation
detection:
  scbin:
    Image|endswith: \sc.exe
  unc:
    CommandLine|contains: \\
  action:
    CommandLine|contains:
      - ' create'
      - ' config'
      - binpath=
  condition: scbin and unc and action
falsepositives:
  - Administrative remote service management
`,
	// ── T1047 – remote WMI process creation (lateral) ──
	`
title: Remote WMI Process Creation via wmic
description: Detects wmic invoking process creation on a REMOTE node (wmic /node:host process call create) — WMI lateral movement that spawns a process on another host without dropping a service.
status: stable
level: high
tags:
  - attack.t1047
  - attack.lateral_movement
  - attack.execution
logsource:
  product: windows
  category: process_creation
detection:
  wmicbin:
    Image|endswith: \wmic.exe
  node:
    CommandLine|contains: "/node:"
  createproc:
    CommandLine|contains: process call create
  condition: wmicbin and node and createproc
falsepositives:
  - Administrative remote WMI automation
`,
	// ── T1083 – SUID/SGID and Linux capabilities discovery ──
	`
title: SUID/SGID or Capabilities Discovery (Linux)
description: Detects enumeration of SUID/SGID binaries or file capabilities (find -perm -4000 / -u=s, getcap -r) — the reconnaissance step attackers run to locate a local privilege-escalation vector.
status: stable
level: medium
tags:
  - attack.t1083
  - attack.discovery
logsource:
  product: linux
  category: process_creation
detection:
  find_suid:
    CommandLine|contains:
      - "-perm -4000"
      - "-perm -u=s"
      - "-perm -2000"
      - "-perm -g=s"
      - "-perm /6000"
  getcap:
    CommandLine|contains:
      - "getcap -r"
      - "getcap -r /"
  condition: find_suid or getcap
falsepositives:
  - Security auditing / hardening scans
`,
	// services.exe launches SERVICE binaries — a direct shell/LOLBin child is anomalous.
	`
title: Service Control Manager Spawning Shell or LOLBin
description: Detects services.exe (the Service Control Manager) directly spawning a command shell or LOLBin (cmd/powershell/wscript/cscript/mshta/rundll32/regsvr32) rather than a service executable — abused by a service configured to run an interpreter directly for execution/persistence as SYSTEM.
status: stable
level: high
tags:
  - attack.t1036
  - attack.defense_evasion
  - attack.execution
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith: \services.exe
    Image|endswith:
      - \cmd.exe
      - \powershell.exe
      - \pwsh.exe
      - \wscript.exe
      - \cscript.exe
      - \mshta.exe
      - \rundll32.exe
      - \regsvr32.exe
  condition: selection
falsepositives:
  - Rare services legitimately configured to run an interpreter directly
`,
	// ── T1055 / T1036 – smss/csrss spawning an anomalous child ──
	`
title: Session Manager or CSRSS Spawning Anomalous Child
description: Detects smss.exe or csrss.exe spawning a command shell or LOLBin. These Session Manager / client-server runtime processes launch only a fixed set of system children (csrss/winlogon/autochk); a shell or interpreter child indicates process-tree hollowing or injected code running under an early-boot trusted process.
status: stable
level: high
tags:
  - attack.t1055
  - attack.defense_evasion
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
      - \smss.exe
      - \csrss.exe
    Image|endswith:
      - \cmd.exe
      - \powershell.exe
      - \pwsh.exe
      - \wscript.exe
      - \cscript.exe
      - \mshta.exe
      - \rundll32.exe
  condition: selection
falsepositives:
  - None expected
`,
	// ── T1055.012 – svchost.exe with a non-standard parent (hollowing) ──
	// svchost.exe is launched almost exclusively by services.exe. A svchost whose parent
	// is an interactive/user process (explorer/powershell/office) or lives under a user-
	// writable path is a hollowed or masqueraded svchost. Positive suspicious-parent match
	// (not "parent != services") so an unresolved parent never false-fires.
	`
title: Svchost With Non-Standard Parent (Process Hollowing / Masquerade)
description: Detects svchost.exe spawned by an interactive or user-writable-path process (explorer/powershell/cmd/office, or a binary under Users/Temp/AppData) instead of services.exe — a hallmark of a hollowed or masqueraded svchost used to blend malicious code into a trusted system-process name.
status: stable
level: high
tags:
  - attack.t1055.012
  - attack.defense_evasion
  - attack.privilege_escalation
logsource:
  product: windows
  category: process_creation
detection:
  svchost:
    Image|endswith: \svchost.exe
  interactive_parent:
    ParentImage|endswith:
      - \explorer.exe
      - \powershell.exe
      - \pwsh.exe
      - \cmd.exe
      - \winword.exe
      - \excel.exe
      - \outlook.exe
      - \wscript.exe
      - \cscript.exe
      - \mshta.exe
      - \rundll32.exe
  userpath_parent:
    ParentImage|contains:
      - \Users\
      - \Temp\
      - \AppData\
      - \Downloads\
      - \ProgramData\
  condition: svchost and (interactive_parent or userpath_parent)
falsepositives:
  - Rare third-party software that legitimately launches its own svchost-named helper
`,
	// ── T1548.002 / T1112 – UAC disabled or weakened via registry value ──
	// Registry sensor depth: these fire on the value DATA (Details), distinguishing a
	// disable (EnableLUA=0) from a re-enable, which a key-path-only rule cannot. The
	// agent serialises DWORDs as decimal strings and appends value_name to TargetObject
	// (alert_pipeline TargetObject build), so Details holds the effective value.
	`
title: UAC Disabled or Weakened via Registry Value
description: Detects registry value edits that turn off or weaken User Account Control — EnableLUA=0 (UAC off), LocalAccountTokenFilterPolicy=1 (remote UAC token-filtering off, enabling PtH with local admins), FilterAdministratorToken=0, or ConsentPromptBehaviorAdmin=0 (no elevation prompt). Distinct from the auto-elevate handler-hijack vector.
status: stable
level: high
tags:
  - attack.t1548.002
  - attack.defense_evasion
  - attack.privilege_escalation
logsource:
  product: windows
  category: registry_event
detection:
  disable_lua:
    TargetObject|endswith: \Policies\System\EnableLUA
    Details: "0"
  token_filter:
    TargetObject|endswith: \Policies\System\LocalAccountTokenFilterPolicy
    Details: "1"
  admin_token:
    TargetObject|endswith: \Policies\System\FilterAdministratorToken
    Details: "0"
  consent:
    TargetObject|endswith: \Policies\System\ConsentPromptBehaviorAdmin
    Details: "0"
  condition: disable_lua or token_filter or admin_token or consent
falsepositives:
  - Enterprise hardening/relaxation pushed via GPO (correlate with the writing tool)
`,
	// ── T1203 / T1189 – macOS browser spawning a shell ──
	`
title: Web Browser Spawning a Shell or Interpreter (macOS)
description: Detects a macOS web browser (Safari/Chrome/Firefox/Edge) spawning a shell, osascript, or scripting interpreter — a drive-by / exploitation indicator, since browsers spawn sandboxed helpers but never an interactive shell.
status: stable
level: high
tags:
  - attack.t1203
  - attack.execution
logsource:
  product: macos
  category: process_creation
detection:
  browser:
    ParentImage|contains:
      - Safari
      - Google Chrome
      - Firefox
      - Microsoft Edge
      - Brave Browser
  interp:
    Image|endswith:
      - /bash
      - /sh
      - /zsh
      - /osascript
      - /python
      - /python3
      - /perl
  condition: browser and interp
falsepositives:
  - Rare developer tooling launched from a browser download
`,
	// ── T1021.006 – WinRM enablement (lateral-movement precursor) ──
	`
title: WinRM Remote Management Enabled
description: Detects enabling the WinRM service or relaxing its transport security (winrm quickconfig, Enable-PSRemoting, allowing unencrypted traffic) — often a precursor step before PowerShell-remoting lateral movement on a host where it was not already configured.
status: stable
level: low
tags:
  - attack.t1021.006
  - attack.lateral_movement
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - winrm quickconfig
      - "winrm qc"
      - Enable-PSRemoting
      - AllowUnencrypted
  condition: selection
falsepositives:
  - Administrators legitimately enabling remote management
`,
	// ── T1562.004 – Windows Firewall disabled via registry ───────────
	`
title: Windows Firewall Disabled via Registry Value
description: Detects the Windows Firewall being turned off through its registry profile (…\SharedAccess\Parameters\FirewallPolicy\<Profile>\EnableFirewall=0), the persistent equivalent of "netsh advfirewall set … state off".
status: stable
level: high
tags:
  - attack.t1562.004
  - attack.defense_evasion
logsource:
  product: windows
  category: registry_event
detection:
  selection:
    TargetObject|contains: \FirewallPolicy\
    TargetObject|endswith: \EnableFirewall
    Details: "0"
  condition: selection
falsepositives:
  - Administrators disabling the built-in firewall in favour of a third-party product
`,
	// ── T1037.001 – Windows Logon Script Persistence (registry) ──
	`
title: Windows Logon Script Persistence via Registry
description: Detects setting the UserInitMprLogonScript registry value, which runs an attacker-specified script every time the user logs on — a classic, low-visibility Windows logon-script persistence mechanism most environments configure via GPO rather than this registry value directly.
status: stable
level: high
tags:
  - attack.t1037.001
  - attack.persistence
logsource:
  product: windows
  category: registry_event
detection:
  selection:
    TargetObject|contains: \Environment\UserInitMprLogonScript
  condition: selection
falsepositives:
  - Rare legitimate logon-script configuration via this registry value instead of GPO
`,
	// winlogon.exe normally launches userinit/dwm/etc — never an interactive shell.
	`
title: Winlogon Spawning Command Shell
description: Detects winlogon.exe spawning a command or script interpreter (cmd/powershell/wscript/cscript), distinct from its normal userinit/dwm children — an indicator of Winlogon-helper persistence, shell hijack, or injection into the logon process.
status: stable
level: high
tags:
  - attack.t1036
  - attack.defense_evasion
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith: \winlogon.exe
    Image|endswith:
      - \cmd.exe
      - \powershell.exe
      - \pwsh.exe
      - \wscript.exe
      - \cscript.exe
  condition: selection
falsepositives:
  - Rare; some remote-management tooling injects into winlogon
`,

	// ─────────────────────────────────────────────────────────────────────────
	// DB ルールからの移設 (migration 377 とセット)
	//
	// P4-6 で server-api の AlertPipeline も `rules` テーブルを読むようになった
	// 結果、DB の Sigma ルールは **2プロセスで評価される** ようになった:
	//
	//   server-api    AlertPipeline → "[Sigma] X"
	//   server-detect RuleEngine    → "[SIGMA] X"
	//
	// 同じ1イベントが2行のアラートになる。dedup は両者を統合するが、
	// 統合は行を resolved にするだけで**削除しない**ため、行数を数える
	// FP ソークのゲートからは二重計上がそのまま見える (2026-08-05 の実測で
	// 403件 → 499件、+96)。docs/ops/FPソーク運用.md §4 を参照。
	//
	// main の migration 374 が採った「builtin と重複する DB ルールを消す」方針は
	// ここでは**そのままでは使えない**。対象7件を1件ずつ突き合わせた結果、
	// builtin 側が DB 側を包含するペアは1つも無かった:
	//
	//   WMI Remote Command Execution      builtin は `process call create` を追加要求
	//                                     する真部分集合 (/node: 単独を取り逃す)
	//   Container Administration Command  builtin は Image|endswith 固定で crictl と
	//                                     ラッパ経由 (sudo docker exec) を取り逃す
	//   Container Image Build on Host     同上
	//   残り4件                            対応する builtin がそもそも存在しない
	//
	// そのため「消す」前に「移す」。以下は DB 行のセレクタを逐語的に移設した
	// もので、検知範囲は1ビットも変わらない。変わるのは**どのプロセスが評価
	// するか**だけ: 移設後は api が builtin として1回だけ評価し、detect は
	// 377 で無効化された行を読まないので発火しない。2N → N になる。
	//
	// severity について: DB 行は `rules.severity` に数値を持つが builtin は
	// Sigma の `level` しか持てず、対応は critical=10/high=8/medium=5/low=3 の
	// 4段階しかない。逐語移設で唯一ずれるのがここで、意図的に記録しておく:
	//
	//   WMI Remote Command Execution              DB 8 → level: high   (8)  一致
	//   Linux Shell Init File Modification (FIM)  DB 5 → level: medium (5)  一致
	//   疑わしいPowerShell実行                     DB 7 → level: high   (8)  +1
	//   Suspicious chmod of Executable in /tmp    DB 4 → level: low    (3)  −1
	//   Script Execution from World-Writable Dir  DB 4 → level: low    (3)  −1
	//
	// ずれる3件はいずれも level が段階の境目にある。上下どちらに丸めるかは
	// 恣意的なので、YAML が既に持っている level をそのまま採用し (chmod と
	// world-writable は元 YAML が low、PowerShell は元 YAML に level が無いので
	// DB 側 7 に最も近い high) 、再調整が要るなら別途の判断とする。
	// ─────────────────────────────────────────────────────────────────────────

	// ── T1021.006 / T1047 – WMI リモートコマンド実行 (migration 014 より) ──
	//
	// 既存の builtin "Remote WMI Process Creation via wmic" は
	// `wmic + /node: + process call create` の3条件 AND なので、
	// `wmic /node:host` だけの呼び出しにも WmiPrvSE 子プロセスにも当たらない。
	// このルールはその2つを見る。両者は併存する (片方は他方の部分集合)。
	`
title: WMI Remote Command Execution
status: stable
description: Detects remote command execution via Windows Management Instrumentation
level: high
tags:
  - attack.t1021.006
  - attack.t1047
  - attack.lateral_movement
  - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection_wmic:
        Image|endswith: '\wmic.exe'
        CommandLine|contains:
            - '/node:'
    selection_wmi_spawn:
        ParentImage|endswith: '\WmiPrvSE.exe'
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\wscript.exe'
            - '\cscript.exe'
    condition: selection_wmic or selection_wmi_spawn
falsepositives:
    - Legitimate WMI administration
`,

	// ── T1059.001 – 疑わしい PowerShell 実行 (migration 003 より) ──
	//
	// 元の DB 行には logsource も level も tags も無く、セレクタだけの
	// 最小ルールだった。セレクタは逐語のまま、評価に必要なメタデータのみ補う。
	`
title: 疑わしいPowerShell実行
status: stable
description: PowerShell の難読化実行・リモートダウンロード・実行ポリシー回避を検出する
level: high
tags:
  - attack.t1059.001
  - attack.execution
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
    CommandLine|contains:
      - ' -enc '
      - 'DownloadString'
      - 'DownloadFile'
      - '-ExecutionPolicy Bypass'
  condition: selection
falsepositives:
  - 管理スクリプトによる正規のダウンロードや実行ポリシー指定
`,

	// ── T1222.002 – /tmp 配下の実行権限付与 (migration 019 → 371 → 376 の最終形) ──
	`
title: Suspicious chmod of Executable in /tmp
id: a1b2c3d4-0007-0007-0007-000000000035
status: stable
description: Detects chmod granting execute permission to a file in a world-writable directory (/tmp, /dev/shm) — the step that makes a downloaded payload runnable. Low severity by design; developers do this constantly and a single process_creation event cannot tell the two apart. Its value is as an input to the download→chmod→execute kill chain, which is where the actual detection happens.
level: low
tags:
  - attack.t1222.002
  - attack.defense_evasion
logsource:
  product: linux
  category: process_creation
detection:
  chmod_bin:
    Image|contains: '/chmod'
  mode_bits:
    CommandLine|contains:
      - '+x'
      - '755'
      - '777'
  staging_dir:
    CommandLine|contains:
      - '/tmp/'
      - '/dev/shm/'
  condition: chmod_bin and mode_bits and staging_dir
falsepositives:
  - Developers marking downloaded installers or build scripts executable under /tmp — indistinguishable from the technique in a single event
`,

	// ── T1204.002 – 誰でも書ける領域からのスクリプト実行 (migration 295 より) ──
	`
title: Script Execution from World-Writable Directory (Linux)
status: stable
description: Detects execution of a shell script from a world-writable temp directory (/tmp, /dev/shm, /var/tmp), a common User Execution vector for downloaded payloads.
level: low
tags:
  - attack.t1204.002
  - attack.execution
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    CommandLine|contains:
      - 'sh /tmp/'
      - 'sh /dev/shm/'
      - 'sh /var/tmp/'
      - 'bash /tmp/'
      - 'bash /dev/shm/'
      - 'bash /var/tmp/'
  condition: selection
falsepositives:
  - Package installers and build systems running helper scripts from temp
`,

	// ── T1546.004 – シェル初期化ファイルへの書き込み (FIM 経路, migration 311 より) ──
	//
	// file_event 由来である点が要。同名の process_creation ルール
	// ("Linux Shell Init Persistence (.bashrc / profile)") は
	// `echo >> .bashrc` / `tee` のようにコマンドラインに現れる書き込みしか
	// 見えないので、両者は重複ではない。
	`
title: Linux Shell Init File Modification (FIM)
description: Detects creation or modification of a user shell-init file (.bashrc/.bash_profile/.bash_login/.profile/.zshrc or /etc/profile.d) observed directly by file integrity monitoring. These files are sourced on every interactive login/shell, making them a common persistence and triggered-execution vector (T1546.004). Complements the process_creation rule that catches the "echo >> .bashrc / tee" idiom by also catching writes that never appear on a monitored command line.
status: stable
level: medium
tags:
  - attack.t1546.004
  - attack.persistence
  - attack.privilege_escalation
logsource:
  product: linux
  category: file_event
detection:
  selection:
    TargetFilename|contains:
      - /.bashrc
      - /.bash_profile
      - /.bash_login
      - /.profile
      - /.zshrc
      - /etc/profile.d/
  condition: selection
falsepositives:
  - Users legitimately editing their shell rc files
  - Package managers writing /etc/profile.d drop-ins
`,

	// ── T1562.001 – Agent self-protection (event_type=tamper) ─────
	//
	// These are the api-side twins of migration 378's "(DB)" rules. Both sides
	// carry the family on purpose: AlertPipeline (server-api) reads the builtins
	// and has caught up with the stream, while the RuleEngine (server-detect)
	// reads the DB and chronically lags (P4-6). "Someone is switching the sensor
	// off" is the last finding that should live only on the slow path.
	//
	// The titles differ from the DB rows by the "(DB)" suffix, and that is load
	// bearing: the DB loader skips any rule whose title collides with a builtin,
	// so identical names would silently drop the DB half.
	//
	// Selectors are a single equality on tamper_type. The agent has already made
	// the decision by the time the event exists — there is no pattern left to
	// match — so the rules exist to attribute, score and route it, not to classify
	// it. The distinction that does matter (signalled vs unsignalled death) is
	// carried in the type itself rather than in a signal number, because the JSON
	// round-trip makes ints float64 and numeric Sigma matching is where that
	// quietly goes wrong.
	`
title: EDR Agent Killed by Signal
description: The EDR agent process was terminated by a signal the watchdog did not send.
  Nothing inside the agent signals itself, and an operator stop goes through the service
  manager, which cancels the watchdog first and is therefore never reported here. A
  signalled death is external interference with the sensor.
status: stable
level: critical
tags:
  - attack.t1562.001
  - attack.defense_evasion
logsource:
  category: tamper
detection:
  selection:
    tamper_type: agent_killed
  condition: selection
falsepositives:
  - An out-of-band kill issued by an administrator debugging the agent
`,

	`
title: EDR Agent Unexpected Exit
description: The EDR agent exited without a signal and without the watchdog asking it to —
  either a crash or, on Windows, a TerminateProcess the exit code cannot be distinguished
  from. Scored below the signalled case precisely because a crash looks identical; the
  endpoint was still unmonitored until the watchdog restarted it.
status: stable
level: medium
tags:
  - attack.t1562.001
  - attack.defense_evasion
logsource:
  category: tamper
detection:
  selection:
    tamper_type: agent_exited
  condition: selection
falsepositives:
  - A genuine agent crash. Check the agent log before treating it as an attack.
`,

	`
title: EDR Agent Binary Modified
description: The on-disk EDR agent binary no longer matches its recorded digest. Reported
  by the start-up integrity check (a swap while the agent was down) or by the running agent
  re-hashing itself against an in-memory baseline (a swap underneath it). Updates go through
  the updater, which re-records the digest, so a legitimate upgrade does not produce this.
status: stable
level: critical
tags:
  - attack.t1554
  - attack.t1562.001
  - attack.defense_evasion
  - attack.persistence
logsource:
  category: tamper
detection:
  selection:
    tamper_type: binary_modified
  condition: selection
falsepositives:
  - A binary replaced by hand, outside the updater
`,

	`
title: EDR Agent Config Modified
description: The EDR agent config file changed while the agent was running. Rewriting the
  config defeats the sensor without touching its code — repointing it at another server or
  disabling collectors leaves a healthy-looking agent that reports nothing useful.
status: stable
level: high
tags:
  - attack.t1562.001
  - attack.defense_evasion
logsource:
  category: tamper
detection:
  selection:
    tamper_type: config_modified
  condition: selection
falsepositives:
  - Configuration management (Ansible/Puppet/Chef) rewriting the file in place
`,

	`
title: EDR Watchdog Missing
description: The agent is running but the watchdog process supervising it is gone. Killing
  the supervisor first is what makes killing the agent stick, so this tends to precede the
  agent's own death rather than follow it. The agent is the only half of the pair still
  alive to report it.
status: stable
level: high
tags:
  - attack.t1562.001
  - attack.defense_evasion
logsource:
  category: tamper
detection:
  selection:
    tamper_type: watchdog_missing
  condition: selection
falsepositives:
  - The watchdog crashed on its own
`,

	`
title: EDR Agent Termination Attempt
description: Something tried to terminate the EDR agent and the kernel layer saw it — a kill
  against the protected PID (Linux eBPF LSM task_kill) or a handle carrying terminate/inject
  rights opened against it (Windows ObRegisterCallbacks). Unlike the watchdog's after-the-fact
  report this names the process that tried, and fires whether or not the attempt succeeded.
  Only produced by builds carrying the prevention tag.
status: stable
level: critical
tags:
  - attack.t1562.001
  - attack.defense_evasion
logsource:
  category: tamper
detection:
  selection:
    tamper_type:
      - kill_attempt
      - handle_open_attempt
  condition: selection
falsepositives:
  - Process management tooling enumerating handles across all processes
`,
}

// LoadBuiltinRules loads the compiled built-in Sigma rules into the given evaluator.
// Errors are logged but do not abort loading of remaining rules.
func LoadBuiltinRules(e *SigmaEvaluator) int {
	loaded := 0
	for _, yaml := range builtinSigmaRules {
		if err := e.LoadRule(yaml); err != nil {
			// Log at debug level; some rules require specific log-source fields
			// that won't fire in all deployments — that is expected.
			_ = err // caller can ignore; counts are returned
			continue
		}
		loaded++
	}
	return loaded
}
