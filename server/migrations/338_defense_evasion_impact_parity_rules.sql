-- 338: detection-server (DB RuleEngine) パリティ 第21弾 — 防御妨害/影響(ログ無効化・権限改変・サービス停止)。
--
-- api-server ビルトインにあるが DB 未移植の高信号3種を移植する:
--   T1562.002 Impair Defenses: Disable Windows Event Logging — auditpol 無効化 /
--             wevtutil sl /e:false / EventLog サービス停止
--   T1222.001 File/Directory Permissions Modification — icacls broad grant / takeown
--   T1489 Service Stop — AV/EDR/バックアップサービスの停止・削除・無効化(ランサム前段)
-- ビルトインは Image|contains を併用するが、DB エンジンでは コマンドライン中の
-- 攻撃固有フレーズを CommandLine|contains(|all アンカー + フラグ)で捕捉する。
-- T1489 は Image ベースの tool 選択を CommandLine 単独へ忠実移植できないため、
-- 動詞(stop/delete/disabled/config)と 対象サービス名(defender/windefend/veeam 等)の
-- 複合条件 action and target で高信号に捕捉する(mig334 Defender 改ざんと同型)。
--
-- platform は linux/windows/macos を明示。冪等化は WHERE NOT EXISTS。
-- 回帰は migration_rules_test.go 群 + migration_parity_test.go(発火)。

-- ── T1562.002 : Windows イベントログ無効化(auditpol / wevtutil / EventLog 停止)──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Windows Event Logging Disabled (DB)', 'sigma', ARRAY['linux','windows','macos'], 8,
$$title: Windows Event Logging Disabled (DB)
description: Detects disabling Windows auditing/event logging — auditpol disabling categories, wevtutil sl /e:false, or stopping the EventLog service.
status: stable
level: high
tags:
  - attack.t1562.002
  - attack.defense_evasion
logsource:
  category: process_creation
detection:
  auditpol:
    CommandLine|contains|all:
      - "auditpol"
    CommandLine|contains:
      - "/success:disable"
      - "/failure:disable"
  wevtutil:
    CommandLine|contains|all:
      - "wevtutil"
      - "sl"
      - "/e:false"
  service:
    CommandLine|contains:
      - "stop-service eventlog"
      - "sc stop eventlog"
      - "stop-service -name eventlog"
  condition: auditpol or wevtutil or service
falsepositives:
  - Authorised audit-policy maintenance
$$,
'builtin-parity', ARRAY['T1562.002'],
'Two-engine parity: Windows event logging disabled (auditpol / wevtutil / EventLog stop)', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Windows Event Logging Disabled (DB)');

-- ── T1222.001 : ファイル/ディレクトリ権限改変(icacls broad grant / takeown)──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'File and Directory Permissions Modification (DB)', 'sigma', ARRAY['linux','windows','macos'], 6,
$$title: File and Directory Permissions Modification (DB)
description: Detects icacls granting broad access (Everyone / S-1-1-0) or takeown seizing ownership — common in ransomware staging and attacker-controlled file setup.
status: stable
level: medium
tags:
  - attack.t1222.001
  - attack.defense_evasion
logsource:
  category: process_creation
detection:
  icacls:
    CommandLine|contains:
      - "/grant Everyone"
      - "/grant *S-1-1-0"
      - "/grant:r everyone"
      - "/T /C /grant"
  takeown:
    CommandLine|contains|all:
      - "takeown"
      - "/f"
  condition: icacls or takeown
falsepositives:
  - Administrative ACL maintenance scripts
$$,
'builtin-parity', ARRAY['T1222.001'],
'Two-engine parity: broad file permission change via icacls/takeown', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'File and Directory Permissions Modification (DB)');

-- ── T1489 : セキュリティ/バックアップサービス停止(AV/EDR/backup tampering)──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Security or Backup Service Tampering (DB)', 'sigma', ARRAY['linux','windows','macos'], 8,
$$title: Security or Backup Service Tampering (DB)
description: Detects stopping/deleting/disabling of antivirus, EDR or backup services (common ransomware pre-encryption step).
status: stable
level: high
tags:
  - attack.t1489
  - attack.impact
logsource:
  category: process_creation
detection:
  action:
    CommandLine|contains:
      - "stop"
      - "delete"
      - "disabled"
      - "config"
  target:
    CommandLine|contains:
      - "defender"
      - "windefend"
      - " sense"
      - "sophos"
      - "crowdstrike"
      - "csagent"
      - "carbonblack"
      - "mcafee"
      - "symantec"
      - "sentinel"
      - "veeam"
      - "backupexec"
      - "sqlwriter"
  condition: action and target
falsepositives:
  - Authorised maintenance of security/backup agents
$$,
'builtin-parity', ARRAY['T1489'],
'Two-engine parity: security/backup service tampering (AV/EDR/backup stop)', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Security or Backup Service Tampering (DB)');
