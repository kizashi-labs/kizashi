-- 354: detection-server (DB RuleEngine) パリティ 第37弾 — リソースハイジャック/ブート改ざん/DCShadow。
--
-- api-server ビルトインにあるが DB 未移植の高信号3種を移植する:
--   T1496     Resource Hijacking       — コインマイナー / stratum マイニングプール接続
--   T1542.003 Bootkit/Boot Config       — bcdedit safeboot/recovery, GRUB 書き換え
--   T1207     Rogue Domain Controller    — DCShadow(不正 DC 登録によるレプリケーション改ざん)
-- ビルトインは一部 Image を併用する。DB エンジンでは コマンドライン中のツール名 +
-- 攻撃固有フレーズで捕捉する。
--
-- platform は linux/windows/macos を明示。冪等化は WHERE NOT EXISTS。
-- 回帰は migration_rules_test.go 群 + migration_parity_test.go(発火)。

-- ── T1496 : リソースハイジャック(コインマイニング)──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Cryptocurrency Mining (DB)', 'sigma', ARRAY['linux','windows','macos'], 7,
$$title: Cryptocurrency Mining (DB)
description: Detects coin-mining software or mining-pool connection patterns (stratum protocol, donate-level) — resource-hijacking impact.
status: stable
level: high
tags:
  - attack.t1496
  - attack.impact
logsource:
  category: process_creation
detection:
  tool:
    CommandLine|contains:
      - "xmrig"
      - "minerd"
      - "cpuminer"
      - "xmr-stak"
      - "nbminer"
      - "phoenixminer"
  cmd:
    CommandLine|contains:
      - "stratum+tcp"
      - "stratum+ssl"
      - "--donate-level"
      - "--cpu-priority"
      - "nicehash"
      - "nanopool"
  condition: tool or cmd
falsepositives:
  - Sanctioned mining on dedicated hardware
$$,
'builtin-parity', ARRAY['T1496'],
'Two-engine parity: cryptocurrency mining (resource hijacking)', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Cryptocurrency Mining (DB)');

-- ── T1542.003 : ブートローダ/ブート構成の改ざん ──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Bootloader or Boot Configuration Tampering (DB)', 'sigma', ARRAY['linux','windows','macos'], 8,
$$title: Bootloader or Boot Configuration Tampering (DB)
description: Detects modification of boot configuration/bootloader (bcdedit safeboot/recovery, GRUB rewrite) for bootkit persistence or recovery disablement.
status: stable
level: high
tags:
  - attack.t1542.003
  - attack.persistence
logsource:
  category: process_creation
detection:
  bcdedit:
    CommandLine|contains|all:
      - "bcdedit"
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
$$,
'builtin-parity', ARRAY['T1542.003'],
'Two-engine parity: bootloader/boot configuration tampering', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Bootloader or Boot Configuration Tampering (DB)');

-- ── T1207 : 不正ドメインコントローラ(DCShadow)──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Rogue Domain Controller DCShadow (DB)', 'sigma', ARRAY['linux','windows','macos'], 9,
$$title: Rogue Domain Controller DCShadow (DB)
description: Detects DCShadow — registering a rogue domain controller to push malicious directory replication (stealthy AD persistence/tampering).
status: stable
level: critical
tags:
  - attack.t1207
  - attack.defense_evasion
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - "dcshadow"
      - "!+ stealth"
      - "/object:"
  condition: selection
falsepositives:
  - Extremely rare; DCShadow has no legitimate use
$$,
'builtin-parity', ARRAY['T1207'],
'Two-engine parity: rogue domain controller (DCShadow)', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Rogue Domain Controller DCShadow (DB)');
