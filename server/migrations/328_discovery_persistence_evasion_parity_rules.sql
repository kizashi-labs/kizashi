-- 328: detection-server (DB RuleEngine) パリティ 第11弾 — 探索/永続化/防御回避。
--
-- api-server ビルトインにあるがDB未移植の探索(グループポリシー)・永続化(ドメイン
-- アカウント作成・at ジョブ)・防御回避(隠しウィンドウ・NTFS 代替データストリーム)を
-- 移植し、両エンジンで被覆する。ビルトインは Image|endswith を併用するが、DB エンジンでは
-- 固有ツール名・フラグ・構文を CommandLine|contains で捕捉する。
--
-- platform は linux/windows/macos を明示。冪等化は WHERE NOT EXISTS。
-- 回帰は migration_rules_test.go 群 + migration_parity_test.go(発火)。

-- ── T1615 : グループポリシー探索 ────────────────────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Group Policy Discovery (DB)', 'sigma', ARRAY['linux','windows','macos'], 5,
$$title: Group Policy Discovery (DB)
description: Detects enumeration of Active Directory Group Policy via gpresult, the GroupPolicy PowerShell cmdlets (Get-GPO/Get-GPOReport/Get-GPResultantSetOfPolicy), or PowerView GPO functions, used to find privilege-escalation and lateral-movement opportunities.
status: stable
level: medium
tags:
  - attack.t1615
  - attack.discovery
logsource:
  category: process_creation
detection:
  gpresult:
    CommandLine|contains: "gpresult"
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
  - Administrators auditing Group Policy
$$,
'builtin-parity', ARRAY['T1615'],
'Two-engine parity: Group Policy discovery', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Group Policy Discovery (DB)');

-- ── T1136.002 : ドメインアカウント作成 ──────────────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Domain Account Creation (DB)', 'sigma', ARRAY['linux','windows','macos'], 7,
$$title: Domain Account Creation (DB)
description: Detects creation of a new domain account via net.exe (net user with /add and /domain), a common persistence and backdoor-account technique after domain compromise.
status: stable
level: high
tags:
  - attack.t1136.002
  - attack.persistence
logsource:
  category: process_creation
detection:
  net_user_add:
    CommandLine|contains|all:
      - "user"
      - "/add"
      - "/domain"
  condition: net_user_add
falsepositives:
  - Legitimate domain administration
$$,
'builtin-parity', ARRAY['T1136.002'],
'Two-engine parity: domain account creation via net.exe', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Domain Account Creation (DB)');

-- ── T1053.002 : At ジョブスケジューリング(レガシー) ─────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'At Job Scheduling (DB)', 'sigma', ARRAY['linux','windows','macos'], 6,
$$title: At Job Scheduling (DB)
description: Detects use of the legacy at.exe scheduler to run an executable, batch file, or command interpreter, an older execution/persistence technique that predates schtasks and is often used to evade task-based monitoring.
status: stable
level: medium
tags:
  - attack.t1053.002
  - attack.execution
  - attack.persistence
logsource:
  category: process_creation
detection:
  at_job:
    CommandLine|contains|all:
      - "at.exe"
    CommandLine|contains:
      - ".exe"
      - ".bat"
      - "cmd"
      - "powershell"
  condition: at_job
falsepositives:
  - Legacy administration scripts still using at
$$,
'builtin-parity', ARRAY['T1053.002'],
'Two-engine parity: at.exe legacy job scheduling', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'At Job Scheduling (DB)');

-- ── T1564.003 : 隠しウィンドウ実行 ─────────────────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Hidden Window Execution (DB)', 'sigma', ARRAY['linux','windows','macos'], 5,
$$title: Hidden Window Execution (DB)
description: Detects PowerShell launched with a hidden window (-w hidden / -WindowStyle Hidden / -w 1) to conceal interactive execution from the user, a common defense-evasion wrapper around a malicious payload.
status: stable
level: medium
tags:
  - attack.t1564.003
  - attack.defense_evasion
logsource:
  category: process_creation
detection:
  hidden:
    CommandLine|contains:
      - " -w hidden"
      - " -w 1 "
      - "-windowstyle hidden"
      - "-windowstyle 1"
  condition: hidden
falsepositives:
  - Some legitimate maintenance scripts run hidden
$$,
'builtin-parity', ARRAY['T1564.003'],
'Two-engine parity: hidden window execution', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Hidden Window Execution (DB)');

-- ── T1564.004 : NTFS 代替データストリーム ──────────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'NTFS Alternate Data Stream Manipulation (DB)', 'sigma', ARRAY['linux','windows','macos'], 6,
$$title: NTFS Alternate Data Stream Manipulation (DB)
description: Detects reading or writing NTFS alternate data streams (-Stream parameter, :$DATA / ::$DATA), used to hide payloads and executables inside a file's alternate streams to evade detection.
status: stable
level: medium
tags:
  - attack.t1564.004
  - attack.defense_evasion
logsource:
  category: process_creation
detection:
  ads:
    CommandLine|contains:
      - " -Stream "
      - ":$DATA"
      - "::$DATA"
  condition: ads
falsepositives:
  - Rare legitimate use of alternate data streams
$$,
'builtin-parity', ARRAY['T1564.004'],
'Two-engine parity: NTFS alternate data stream manipulation', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'NTFS Alternate Data Stream Manipulation (DB)');
