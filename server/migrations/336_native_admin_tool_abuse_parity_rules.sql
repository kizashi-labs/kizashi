-- 336: detection-server (DB RuleEngine) パリティ 第19弾 — ネイティブ管理ツール悪用。
--
-- 攻撃者が正規の Windows 管理ツールを実行/永続化/権限昇格に流用するコア3種を
-- 移植する。いずれも api-server ビルトインにあるが DB 未移植:
--   T1053.005 Scheduled Task/Job         — schtasks /create / Register-ScheduledTask
--   T1543.003 Create/Modify System Proc  — sc create binPath= / New-Service
--   T1136.001 + T1098 Account Manipulation — net user /add / net localgroup administrators /add
-- ビルトインは Image|contains を併用するが、DB エンジンでは コマンドライン中の
-- バイナリ名 + 攻撃固有フラグを CommandLine|contains(|all アンカー + フラグ)で
-- 捕捉する(死蔵回避、mig325 InstallUtil と同型)。
--
-- platform は linux/windows/macos を明示。冪等化は WHERE NOT EXISTS。
-- 回帰は migration_rules_test.go 群 + migration_parity_test.go(発火)。

-- ── T1053.005 : スケジュールタスク作成(schtasks / Register-ScheduledTask)──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Scheduled Task Creation (DB)', 'sigma', ARRAY['linux','windows','macos'], 6,
$$title: Scheduled Task Creation (DB)
description: Detects scheduled task creation via schtasks /create or PowerShell Register-ScheduledTask (persistence/execution).
status: stable
level: medium
tags:
  - attack.t1053.005
  - attack.persistence
  - attack.execution
logsource:
  category: process_creation
detection:
  schtasks:
    CommandLine|contains|all:
      - "schtasks"
      - "/create"
  ps_register:
    CommandLine|contains: "Register-ScheduledTask"
  condition: schtasks or ps_register
falsepositives:
  - Legitimate administrative or software-installer scheduled tasks
$$,
'builtin-parity', ARRAY['T1053.005'],
'Two-engine parity: scheduled task creation (schtasks / Register-ScheduledTask)', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Scheduled Task Creation (DB)');

-- ── T1543.003 : Windows サービス作成(sc create binPath / New-Service)──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Windows Service Creation (DB)', 'sigma', ARRAY['linux','windows','macos'], 7,
$$title: Windows Service Creation (DB)
description: Detects new Windows service creation via sc create binPath= or PowerShell New-Service (persistence/privilege escalation).
status: stable
level: high
tags:
  - attack.t1543.003
  - attack.persistence
  - attack.privilege_escalation
logsource:
  category: process_creation
detection:
  sc:
    CommandLine|contains|all:
      - "create"
      - "binpath"
  ps_newservice:
    CommandLine|contains: "New-Service"
  condition: sc or ps_newservice
falsepositives:
  - Legitimate software installation
$$,
'builtin-parity', ARRAY['T1543.003'],
'Two-engine parity: Windows service creation (sc binPath / New-Service)', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Windows Service Creation (DB)');

-- ── T1136.001 + T1098 : ローカルアカウント作成 / 管理者グループ追加(net.exe)──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Local Account and Admin Group Manipulation (DB)', 'sigma', ARRAY['linux','windows','macos'], 7,
$$title: Local Account and Admin Group Manipulation (DB)
description: Detects local account creation (net user /add) or addition of an account to the local Administrators group (net localgroup administrators /add).
status: stable
level: high
tags:
  - attack.t1136.001
  - attack.t1098
  - attack.persistence
  - attack.privilege_escalation
logsource:
  category: process_creation
detection:
  net_user:
    CommandLine|contains|all:
      - "net user"
      - "/add"
  net_localadmin:
    CommandLine|contains|all:
      - "localgroup"
      - "/add"
    CommandLine|contains:
      - "administ"
  condition: net_user or net_localadmin
falsepositives:
  - Legitimate account provisioning or group management by IT
$$,
'builtin-parity', ARRAY['T1136.001','T1098'],
'Two-engine parity: local account creation / admin group addition via net.exe', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Local Account and Admin Group Manipulation (DB)');
