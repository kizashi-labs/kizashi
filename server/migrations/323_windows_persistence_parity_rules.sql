-- 323: detection-server (DB RuleEngine) パリティ 第6弾 — Windows 永続化。
--
-- api-server ビルトインにあるがDBエンジン未移植の Windows レジストリ/LOLBin 永続化を移植し、
-- 両エンジンで被覆する。ビルトインは Image|contains/endswith を併用するが、DB エンジンでは
-- 固有のレジストリ値名・BITS フラグを CommandLine|contains で捕捉する(死蔵回避)。
--
-- platform は linux/windows/macos を明示(イベントOS未設定でも取りこぼさないようフェイルオープン。
-- 実質 Windows 固有だが、DB の platform gate で誤って除外されるのを避ける)。
-- 冪等化は WHERE NOT EXISTS。回帰は migration_rules_test.go 群 + migration_parity_test.go。

-- ── T1546.001 : AppInit DLLs 永続化 ───────────────────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'AppInit DLLs Persistence (DB)', 'sigma', ARRAY['linux','windows','macos'], 7,
$$title: AppInit DLLs Persistence (DB)
description: Detects setting the AppInit_DLLs or LoadAppInit_DLLs registry values, which force every user-mode process that loads user32.dll to also load an attacker DLL, a stealthy system-wide persistence and privilege-escalation foothold.
status: stable
level: high
tags:
  - attack.t1546.001
  - attack.persistence
  - attack.privilege_escalation
logsource:
  category: process_creation
detection:
  appinit:
    CommandLine|contains:
      - "AppInit_DLLs"
      - "LoadAppInit_DLLs"
  condition: appinit
falsepositives:
  - Rare legacy software that legitimately registers an AppInit DLL
$$,
'builtin-parity', ARRAY['T1546.001'],
'Two-engine parity: AppInit DLLs persistence', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'AppInit DLLs Persistence (DB)');

-- ── T1037.001 : ログオンスクリプト永続化 ─────────────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Logon Script Persistence (DB)', 'sigma', ARRAY['linux','windows','macos'], 7,
$$title: Logon Script Persistence (DB)
description: Detects setting the UserInitMprLogonScript registry value under the user Environment key, which runs an attacker-specified script at every interactive logon, a classic user-scoped persistence mechanism.
status: stable
level: high
tags:
  - attack.t1037.001
  - attack.persistence
  - attack.privilege_escalation
logsource:
  category: process_creation
detection:
  logon_script:
    CommandLine|contains: "UserInitMprLogonScript"
  condition: logon_script
falsepositives:
  - Rare legitimate logon-script configuration by administrators
$$,
'builtin-parity', ARRAY['T1037.001'],
'Two-engine parity: logon script persistence (UserInitMprLogonScript)', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Logon Script Persistence (DB)');

-- ── T1546.012 : IFEO デバッガ永続化 ──────────────────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Image File Execution Options Debugger (DB)', 'sigma', ARRAY['linux','windows','macos'], 7,
$$title: Image File Execution Options Debugger (DB)
description: Detects setting a Debugger value under Image File Execution Options, hijacking execution of a target program (e.g. sethc.exe, an accessibility binary) for persistence or privilege escalation.
status: stable
level: high
tags:
  - attack.t1546.012
  - attack.persistence
  - attack.privilege_escalation
logsource:
  category: process_creation
detection:
  ifeo:
    CommandLine|contains|all:
      - "Image File Execution Options"
      - "Debugger"
  condition: ifeo
falsepositives:
  - GFlags or debugging tools configuring a debugger intentionally
$$,
'builtin-parity', ARRAY['T1546.012'],
'Two-engine parity: IFEO Debugger hijack persistence', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Image File Execution Options Debugger (DB)');

-- ── T1197 : BITS ジョブ(LOLBin ダウンロード/永続化) ──────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'BITS Jobs Abuse (DB)', 'sigma', ARRAY['linux','windows','macos'], 6,
$$title: BITS Jobs Abuse (DB)
description: Detects bitsadmin or PowerShell BITS transfers used to download payloads or persist via a notify command line, a stealthy living-off-the-land technique (bitsadmin /transfer /addfile /setnotifycmdline, Start-BitsTransfer, Import-Module BitsTransfer).
status: stable
level: medium
tags:
  - attack.t1197
  - attack.defense_evasion
  - attack.persistence
logsource:
  category: process_creation
detection:
  bitsadmin:
    CommandLine|contains|all:
      - "bitsadmin"
    CommandLine|contains:
      - "/transfer"
      - "/create"
      - "/addfile"
      - "/setnotifycmdline"
  ps_bits:
    CommandLine|contains:
      - "Start-BitsTransfer"
      - "Import-Module BitsTransfer"
  condition: bitsadmin or ps_bits
falsepositives:
  - Legitimate software updaters that use BITS
$$,
'builtin-parity', ARRAY['T1197'],
'Two-engine parity: BITS jobs download/persistence abuse', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'BITS Jobs Abuse (DB)');
