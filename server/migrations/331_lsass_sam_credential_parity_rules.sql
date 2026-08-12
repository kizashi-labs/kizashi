-- 331: detection-server (DB RuleEngine) パリティ 第14弾 — LSASS/SAM 資格情報ダンプ補完。
--
-- mig324(資格情報アクセス)では T1003.003/004/005 等を移植したが、最重要の
-- OS 資格情報ダンプ 2種 — T1003.001(LSASS メモリ)と T1003.002(SAM ハイブ)—
-- が DB 未移植だった。api-server ビルトインにあるこれらを DB へ移植し、両エンジンで
-- 被覆する。ビルトインは Image|contains を併用するが、DB エンジンでは バイナリ名/
-- ツール名 + 攻撃固有指標を CommandLine|contains で捕捉する(死蔵回避)。
--
-- SAM ハイブは backslash の YAML エスケープ罠(\s は不正エスケープ)を避けるため
-- "save"/"HKLM"/"SAM" の3トークン(contains は大小無視)で hklm\sam を表現する。
--
-- platform は linux/windows/macos を明示。冪等化は WHERE NOT EXISTS。
-- 回帰は migration_rules_test.go 群 + migration_parity_test.go(発火)。

-- ── T1003.001 : LSASS メモリダンプ(comsvcs / 専用ツール / ProcDump)──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'LSASS Memory Dump (DB)', 'sigma', ARRAY['linux','windows','macos'], 9,
$$title: LSASS Memory Dump (DB)
status: stable
level: critical
tags:
  - attack.t1003.001
  - attack.credential_access
logsource:
  category: process_creation
detection:
  tools:
    CommandLine|contains:
      - "nanodump"
      - "dumpert"
      - "handlekatz"
      - "Out-Minidump"
      - "pypykatz"
      - "lsassy"
      - "safetykatz"
      - "Invoke-Mimikatz"
  comsvcs_dll:
    CommandLine|contains: "comsvcs"
  comsvcs_method:
    CommandLine|contains:
      - "MiniDump"
      - "#24"
  procdump:
    CommandLine|contains|all:
      - "procdump"
      - "lsass"
  condition: tools or (comsvcs_dll and comsvcs_method) or procdump
falsepositives:
  - Authorised crash-dump collection of lsass for debugging
$$,
'builtin-parity', ARRAY['T1003.001'],
'Two-engine parity: LSASS memory dump (comsvcs/tools/ProcDump)', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'LSASS Memory Dump (DB)');

-- ── T1003.002 : SAM ハイブダンプ(reg save HKLM\SAM)──────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'SAM Hive Dump (DB)', 'sigma', ARRAY['linux','windows','macos'], 8,
$$title: SAM Hive Dump (DB)
status: stable
level: high
tags:
  - attack.t1003.002
  - attack.credential_access
logsource:
  category: process_creation
detection:
  sam_save:
    CommandLine|contains|all:
      - "save"
      - "HKLM"
      - "SAM"
  condition: sam_save
falsepositives:
  - Rare legitimate backup of registry hives
$$,
'builtin-parity', ARRAY['T1003.002'],
'Two-engine parity: SAM registry hive dump for credential access', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'SAM Hive Dump (DB)');
