-- 348: detection-server (DB RuleEngine) パリティ 第31弾 — macOS 永続化。
--
-- api-server ビルトインにあるが DB 未移植の macOS 永続化3種を移植する:
--   T1543.001 (+T1547.011) Launch Agent/Daemon — launchctl load / plist 書き込み
--   T1547.015 Login Items                       — osascript で make login item
--   T1546.014 Emond Rule                        — emond ルール plist 作成
-- ビルトインは一部 Image を併用する。DB エンジンでは コマンドライン中のツール名 +
-- 対象パス/フレーズで捕捉する。
--
-- 備考: Linux cron 永続化(T1053.003)は file_event(TargetFilename/Contents)ベースで
-- CommandLine のみの DB エンジンへ忠実移植できないため本バッチから除外。
--
-- platform は linux/windows/macos を明示。冪等化は WHERE NOT EXISTS。
-- 回帰は migration_rules_test.go 群 + migration_parity_test.go(発火)。

-- ── T1543.001 / T1547.011 : Launch Agent/Daemon 永続化(launchctl / plist)──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'macOS Launch Agent Daemon Persistence (DB)', 'sigma', ARRAY['linux','windows','macos'], 8,
$$title: macOS Launch Agent Daemon Persistence (DB)
description: Detects launchd persistence — launchctl loading/bootstrapping a service or writing a plist into LaunchAgents/LaunchDaemons.
status: stable
level: high
tags:
  - attack.t1543.001
  - attack.t1547.011
  - attack.persistence
logsource:
  category: process_creation
detection:
  launchctl:
    CommandLine|contains|all:
      - "launchctl"
    CommandLine|contains:
      - "LaunchDaemons"
      - "LaunchAgents"
      - "bootstrap"
      - "load -w"
  pw_tool:
    CommandLine|contains:
      - "tee"
      - "cp"
      - "mv"
  pw_path:
    CommandLine|contains:
      - "/Library/LaunchDaemons/"
      - "/Library/LaunchAgents/"
  condition: launchctl or (pw_tool and pw_path)
falsepositives:
  - Installers registering legitimate launch services
$$,
'builtin-parity', ARRAY['T1543.001','T1547.011'],
'Two-engine parity: macOS launch agent/daemon persistence', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'macOS Launch Agent Daemon Persistence (DB)');

-- ── T1547.015 : Login Items 永続化(osascript make login item)──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'macOS Login Item Persistence (DB)', 'sigma', ARRAY['linux','windows','macos'], 5,
$$title: macOS Login Item Persistence (DB)
description: Detects creation of a Login Item via AppleScript (System Events make login item) — user-scope persistence.
status: stable
level: medium
tags:
  - attack.t1547.015
  - attack.persistence
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains|all:
      - "osascript"
    CommandLine|contains:
      - "login item"
      - "make login item"
      - "make new login item"
  condition: selection
falsepositives:
  - Apps legitimately registering a login item
$$,
'builtin-parity', ARRAY['T1547.015'],
'Two-engine parity: macOS login item persistence', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'macOS Login Item Persistence (DB)');

-- ── T1546.014 : Emond ルール永続化 ──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'macOS Emond Rule Persistence (DB)', 'sigma', ARRAY['linux','windows','macos'], 8,
$$title: macOS Emond Rule Persistence (DB)
description: Detects creation of an Event Monitor (emond) rule plist — an under-watched macOS persistence mechanism.
status: stable
level: high
tags:
  - attack.t1546.014
  - attack.persistence
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - "/etc/emond.d/rules"
      - "/private/var/db/emondClients"
      - "emond.d/rules"
  condition: selection
falsepositives:
  - Essentially none; emond is deprecated and rarely used legitimately
$$,
'builtin-parity', ARRAY['T1546.014'],
'Two-engine parity: macOS emond rule persistence', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'macOS Emond Rule Persistence (DB)');
