-- 341: detection-server (DB RuleEngine) パリティ 第24弾 — 横展開/リモート実行。
--
-- api-server ビルトインにあるが DB 未移植のリモート実行/横展開3種を移植する:
--   T1047     WMIC Process Call Create — wmic process call create(実行/横展開)
--   T1021.006 WinRM                    — winrs / Enter-PSSession / evil-winrm
--   T1021.004 SSH inline creds         — plink -pw / sshpass -p(資格情報付き横展開)
-- ビルトインは Image|contains を併用するが、DB エンジンでは コマンドライン中の
-- バイナリ名 + 攻撃固有フラグを CommandLine|contains(|all アンカー)で捕捉する。
--
-- platform は linux/windows/macos を明示。冪等化は WHERE NOT EXISTS。
-- 回帰は migration_rules_test.go 群 + migration_parity_test.go(発火)。

-- ── T1047 : WMIC プロセス生成(process call create)──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'WMIC Process Call Create (DB)', 'sigma', ARRAY['linux','windows','macos'], 7,
$$title: WMIC Process Call Create (DB)
description: Detects wmic spawning processes via "process call create" — execution and lateral movement.
status: stable
level: high
tags:
  - attack.t1047
  - attack.execution
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains|all:
      - "wmic"
      - "process"
      - "call"
      - "create"
  condition: selection
falsepositives:
  - Legitimate administrative WMI scripting
$$,
'builtin-parity', ARRAY['T1047'],
'Two-engine parity: WMIC process call create (execution/lateral movement)', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'WMIC Process Call Create (DB)');

-- ── T1021.006 : WinRM 横展開(winrs / PowerShell Remoting / evil-winrm)──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'WinRM Lateral Movement (DB)', 'sigma', ARRAY['linux','windows','macos'], 6,
$$title: WinRM Lateral Movement (DB)
description: Detects remote command execution over WinRM — winrs, PowerShell remoting (Enter-PSSession/New-PSSession), or evil-winrm.
status: stable
level: medium
tags:
  - attack.t1021.006
  - attack.lateral_movement
logsource:
  category: process_creation
detection:
  winrs:
    CommandLine|contains: "winrs"
  pssession:
    CommandLine|contains:
      - "Enter-PSSession"
      - "New-PSSession"
  evil_winrm:
    CommandLine|contains: "evil-winrm"
  condition: winrs or pssession or evil_winrm
falsepositives:
  - Administrators using PowerShell remoting / winrs for management
$$,
'builtin-parity', ARRAY['T1021.006'],
'Two-engine parity: WinRM lateral movement (winrs / PS remoting / evil-winrm)', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'WinRM Lateral Movement (DB)');

-- ── T1021.004 : SSH 資格情報付き横展開(plink -pw / sshpass -p)──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'SSH Lateral Movement with Inline Credentials (DB)', 'sigma', ARRAY['linux','windows','macos'], 6,
$$title: SSH Lateral Movement with Inline Credentials (DB)
description: Detects scripted SSH with the password supplied on the command line (plink -pw, sshpass -p) — a hallmark of credentialed lateral movement.
status: stable
level: medium
tags:
  - attack.t1021.004
  - attack.lateral_movement
logsource:
  category: process_creation
detection:
  plink:
    CommandLine|contains|all:
      - "plink"
      - " -pw "
  sshpass:
    CommandLine|contains|all:
      - "sshpass"
      - " -p "
  condition: plink or sshpass
falsepositives:
  - Legitimate automation that embeds SSH credentials (discouraged)
$$,
'builtin-parity', ARRAY['T1021.004'],
'Two-engine parity: SSH lateral movement with inline credentials (plink/sshpass)', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'SSH Lateral Movement with Inline Credentials (DB)');
