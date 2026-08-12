-- 329: detection-server (DB RuleEngine) パリティ 第12弾 — WMI購読/MOTW/残りLOLBin。
--
-- api-server ビルトインにあるがDB未移植の高価値な永続化・防御回避・実行を移植:
-- WMI イベント購読永続化、Mark-of-the-Web 回避、コンパイル済みHTML(hh.exe)、UPX パッキング、
-- PsExec サービス実行。ビルトインは Image を併用するが、DB エンジンでは固有トークンを
-- CommandLine|contains で捕捉する(死蔵回避)。
--
-- platform は linux/windows/macos を明示。冪等化は WHERE NOT EXISTS。
-- 回帰は migration_rules_test.go 群 + migration_parity_test.go(発火)。

-- ── T1546.003 : WMI イベント購読永続化 ──────────────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'WMI Event Subscription Persistence (DB)', 'sigma', ARRAY['linux','windows','macos'], 8,
$$title: WMI Event Subscription Persistence (DB)
description: Detects creation of a WMI permanent event subscription for persistence (__EventFilter, __EventConsumer, __FilterToConsumerBinding, ActiveScript/CommandLine event consumers, Register-WmiEvent/Register-CimIndicationEvent), which runs attacker code on a trigger and survives reboot.
status: stable
level: high
tags:
  - attack.t1546.003
  - attack.persistence
  - attack.privilege_escalation
logsource:
  category: process_creation
detection:
  wmi_sub:
    CommandLine|contains:
      - "__EventConsumer"
      - "__EventFilter"
      - "__FilterToConsumerBinding"
      - "ActiveScriptEventConsumer"
      - "CommandLineEventConsumer"
      - "Register-WmiEvent"
      - "Register-CimIndicationEvent"
  condition: wmi_sub
falsepositives:
  - Legitimate management software using WMI subscriptions (rare)
$$,
'builtin-parity', ARRAY['T1546.003'],
'Two-engine parity: WMI event subscription persistence', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'WMI Event Subscription Persistence (DB)');

-- ── T1553.005 : Mark-of-the-Web 回避 ────────────────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Mark-of-the-Web Bypass (DB)', 'sigma', ARRAY['linux','windows','macos'], 6,
$$title: Mark-of-the-Web Bypass (DB)
description: Detects removal of the Mark-of-the-Web to bypass SmartScreen/protected-view warnings on downloaded files (PowerShell Unblock-File, deleting the Zone.Identifier alternate data stream, or sysinternals streams -d).
status: stable
level: medium
tags:
  - attack.t1553.005
  - attack.defense_evasion
logsource:
  category: process_creation
detection:
  motw:
    CommandLine|contains:
      - "Unblock-File"
      - ":Zone.Identifier"
      - "streams -d"
  condition: motw
falsepositives:
  - Users legitimately unblocking a trusted downloaded file
$$,
'builtin-parity', ARRAY['T1553.005'],
'Two-engine parity: Mark-of-the-Web bypass', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Mark-of-the-Web Bypass (DB)');

-- ── T1218.001 : コンパイル済みHTML遠隔実行(hh.exe) ──────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Compiled HTML Help Remote Execution (DB)', 'sigma', ARRAY['linux','windows','macos'], 7,
$$title: Compiled HTML Help Remote Execution (DB)
description: Detects hh.exe (Compiled HTML Help) fetching a .chm from a remote URL, a LOLBin proxy-execution technique that runs script embedded in the help file through a signed Microsoft binary.
status: stable
level: high
tags:
  - attack.t1218.001
  - attack.defense_evasion
logsource:
  category: process_creation
detection:
  hh_remote:
    CommandLine|contains|all:
      - "hh.exe"
    CommandLine|contains:
      - "http://"
      - "https://"
      - "ftp://"
  condition: hh_remote
falsepositives:
  - Rare; hh.exe normally opens local .chm help files
$$,
'builtin-parity', ARRAY['T1218.001'],
'Two-engine parity: compiled HTML help (hh.exe) remote execution', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Compiled HTML Help Remote Execution (DB)');

-- ── T1027.002 : ソフトウェアパッキング(UPX) ────────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Software Packing via UPX (DB)', 'sigma', ARRAY['linux','windows','macos'], 5,
$$title: Software Packing via UPX (DB)
description: Detects use of the UPX packer to compress/obfuscate an executable (upx -o output, upx --best, upx.exe), used to evade static/signature-based detection.
status: stable
level: medium
tags:
  - attack.t1027.002
  - attack.defense_evasion
logsource:
  category: process_creation
detection:
  upx:
    CommandLine|contains:
      - "upx "
      - "upx.exe"
      - "upx -d"
      - "upx --best"
      - "upx -o"
  condition: upx
falsepositives:
  - Legitimate developers packing their own release binaries
$$,
'builtin-parity', ARRAY['T1027.002'],
'Two-engine parity: software packing via UPX', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Software Packing via UPX (DB)');

-- ── T1569.002 : PsExec サービス実行 ────────────────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'PsExec Service Execution (DB)', 'sigma', ARRAY['linux','windows','macos'], 7,
$$title: PsExec Service Execution (DB)
description: Detects PsExec service execution (PSEXESVC service or the psexec client with -accepteula), commonly used for remote command execution and lateral movement.
status: stable
level: high
tags:
  - attack.t1569.002
  - attack.execution
  - attack.lateral_movement
logsource:
  category: process_creation
detection:
  psexec:
    CommandLine|contains:
      - "PSEXESVC"
      - "psexec "
      - "psexec.exe"
      - "paexec"
  condition: psexec
falsepositives:
  - Legitimate administrative use of PsExec
$$,
'builtin-parity', ARRAY['T1569.002'],
'Two-engine parity: PsExec service execution', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'PsExec Service Execution (DB)');
