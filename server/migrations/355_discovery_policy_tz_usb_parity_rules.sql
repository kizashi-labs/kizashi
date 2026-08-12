-- 355: detection-server (DB RuleEngine) パリティ 第38弾 — ディスカバリ第3弾/リムーバブルメディア。
--
-- api-server ビルトインにあるが DB 未移植の3種を移植する:
--   T1201     Password Policy Discovery  — /etc/login.defs, chage -l, net accounts 等
--   T1614.001 System Location/Timezone    — timedatectl, /etc/timezone, tzutil 等
--   T1091     Removable Media Replication  — autorun.inf の設置
-- いずれもコマンドライン主体。Windows 相当(net accounts / tzutil)を補足追加している。
--
-- 備考: T1091 の「実行ファイルをリムーバブルドライブ(D:\ 等)へコピー」分岐は
-- ドライブレターのバックスラッシュが YAML エスケープ問題となるため除外し、
-- autorun.inf 設置(最も特徴的な指標)で捕捉する。
--
-- platform は linux/windows/macos を明示。冪等化は WHERE NOT EXISTS。
-- 回帰は migration_rules_test.go 群 + migration_parity_test.go(発火)。

-- ── T1201 : パスワードポリシー列挙 ──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Password Policy Discovery (DB)', 'sigma', ARRAY['linux','windows','macos'], 4,
$$title: Password Policy Discovery (DB)
description: Detects reading the system password policy or per-account aging (login.defs, chage -l, passwd -S, net accounts) to tune spray/brute-force and avoid lockout.
status: stable
level: low
tags:
  - attack.t1201
  - attack.discovery
logsource:
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
      - "net accounts"
  condition: selection
falsepositives:
  - Configuration management reading password policy
$$,
'builtin-parity', ARRAY['T1201'],
'Two-engine parity: password policy discovery', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Password Policy Discovery (DB)');

-- ── T1614.001 : システムロケーション/タイムゾーン列挙 ──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'System Location and Timezone Discovery (DB)', 'sigma', ARRAY['linux','windows','macos'], 4,
$$title: System Location and Timezone Discovery (DB)
description: Detects discovery of host timezone/locale (timedatectl, /etc/timezone, systemsetup -gettimezone, tzutil) to fingerprint victim geography.
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
      - "timedatectl"
      - "/etc/timezone"
      - "/etc/localtime"
      - "systemsetup -gettimezone"
      - "systemsetup -getnetworktimeserver"
      - "tzutil"
  condition: selection
falsepositives:
  - Time-synchronization / provisioning tooling
$$,
'builtin-parity', ARRAY['T1614.001'],
'Two-engine parity: system location and timezone discovery', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'System Location and Timezone Discovery (DB)');

-- ── T1091 : リムーバブルメディア複製(autorun.inf 設置)──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Removable Media Replication (DB)', 'sigma', ARRAY['linux','windows','macos'], 5,
$$title: Removable Media Replication (DB)
description: Detects staging of an autorun.inf payload used to spread across USB/removable-media-connected hosts.
status: stable
level: medium
tags:
  - attack.t1091
  - attack.lateral_movement
logsource:
  category: process_creation
detection:
  autorun:
    CommandLine|contains: "autorun.inf"
  condition: autorun
falsepositives:
  - Rare; autorun.inf authoring is uncommon on modern systems
$$,
'builtin-parity', ARRAY['T1091'],
'Two-engine parity: removable media replication (autorun.inf)', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Removable Media Replication (DB)');
