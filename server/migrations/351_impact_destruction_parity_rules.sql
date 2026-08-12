-- 351: detection-server (DB RuleEngine) パリティ 第34弾 — 影響/破壊(Impact)。
--
-- api-server ビルトインにあるが DB 未移植の破壊系3種を移植する:
--   T1485 Data Destruction        — cipher /w, sdelete, shred による安全消去
--   T1531 Account Access Removal   — net user /delete, /active:no, Remove-ADUser 等
--   T1561 Disk Wipe               — Clear-Disk, diskpart clean, format /p:, 物理ドライブ書込
-- ビルトインは一部 Image を併用する。DB エンジンでは コマンドライン中のツール名 +
-- 破壊固有フラグで捕捉する。物理ドライブパス `\\.\PHYSICALDRIVE` は YAML バックスラッシュ
-- 問題を避け "PHYSICALDRIVE" 単体で捕捉する。
--
-- platform は linux/windows/macos を明示。冪等化は WHERE NOT EXISTS。
-- 回帰は migration_rules_test.go 群 + migration_parity_test.go(発火)。

-- ── T1485 : データ破壊(cipher/sdelete/shred)──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Data Destruction via Wiping Utility (DB)', 'sigma', ARRAY['linux','windows','macos'], 8,
$$title: Data Destruction via Wiping Utility (DB)
description: Detects secure-wipe/data-destruction tooling overwriting files or free space (cipher /w, sdelete, shred).
status: stable
level: high
tags:
  - attack.t1485
  - attack.impact
logsource:
  category: process_creation
detection:
  cipher:
    CommandLine|contains|all:
      - "cipher"
      - "/w"
  sdelete:
    CommandLine|contains: "sdelete"
  shred:
    CommandLine|contains:
      - "shred -"
      - "shred --"
  condition: cipher or sdelete or shred
falsepositives:
  - Authorised secure deletion of sensitive data
$$,
'builtin-parity', ARRAY['T1485'],
'Two-engine parity: data destruction via wiping utility', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Data Destruction via Wiping Utility (DB)');

-- ── T1531 : アカウントアクセス剥奪(削除/無効化)──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Account Access Removal (DB)', 'sigma', ARRAY['linux','windows','macos'], 8,
$$title: Account Access Removal (DB)
description: Detects deletion/disabling of accounts (net user /delete, /active:no, Remove/Disable-AD/LocalUser) to lock out legitimate users during impact.
status: stable
level: high
tags:
  - attack.t1531
  - attack.impact
logsource:
  category: process_creation
detection:
  netuser:
    CommandLine|contains|all:
      - "net user"
      - "/delete"
  disable:
    CommandLine|contains:
      - "/active:no"
      - "Disable-ADAccount"
      - "Remove-ADUser"
      - "Remove-LocalUser"
  condition: netuser or disable
falsepositives:
  - Routine deprovisioning of departed users
$$,
'builtin-parity', ARRAY['T1531'],
'Two-engine parity: account access removal', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Account Access Removal (DB)');

-- ── T1561 : ディスクワイプ/破壊 ──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Disk Wipe or Destruction (DB)', 'sigma', ARRAY['linux','windows','macos'], 9,
$$title: Disk Wipe or Destruction (DB)
description: Detects destructive disk operations — Clear-Disk, raw physical-drive writes, diskpart clean, or multi-pass format — rendering systems unrecoverable.
status: stable
level: critical
tags:
  - attack.t1561
  - attack.impact
logsource:
  category: process_creation
detection:
  clear:
    CommandLine|contains:
      - "Clear-Disk"
      - "PHYSICALDRIVE"
  diskpart:
    CommandLine|contains|all:
      - "diskpart"
      - "clean"
  format:
    CommandLine|contains|all:
      - "format.com"
      - "/p:"
  condition: clear or diskpart or format
falsepositives:
  - Authorised disk provisioning or secure decommissioning
$$,
'builtin-parity', ARRAY['T1561'],
'Two-engine parity: disk wipe or destruction', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Disk Wipe or Destruction (DB)');
