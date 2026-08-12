-- 352: detection-server (DB RuleEngine) パリティ 第35弾 — 防御回避/痕跡隠蔽・setuid付与。
--
-- api-server ビルトインにあるが DB 未移植の3種を移植する:
--   T1564.001 Hidden File/Directory  — attrib +h +s によるファイル秘匿
--   T1222.002 Setuid/Setgid          — chmod u+s / 4755 等での特権ビット付与
--   T1070.003 Clear Command History   — history -c / unset HISTFILE 等の履歴消去
-- ビルトインは一部 Image を併用する。DB エンジンでは コマンドライン中のツール名 +
-- 攻撃固有フラグで捕捉する(attrib/chmod は |all アンカー、履歴消去は逐語移植)。
--
-- platform は linux/windows/macos を明示。冪等化は WHERE NOT EXISTS。
-- 回帰は migration_rules_test.go 群 + migration_parity_test.go(発火)。

-- ── T1564.001 : attrib による隠しファイル/ディレクトリ ──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Hidden File or Directory via attrib (DB)', 'sigma', ARRAY['linux','windows','macos'], 5,
$$title: Hidden File or Directory via attrib (DB)
description: Detects attrib.exe setting hidden+system attributes to conceal malicious files/directories.
status: stable
level: medium
tags:
  - attack.t1564.001
  - attack.defense_evasion
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains|all:
      - "attrib"
      - "+h"
      - "+s"
  condition: selection
falsepositives:
  - Some installers mark configuration files hidden+system
$$,
'builtin-parity', ARRAY['T1564.001'],
'Two-engine parity: hidden file/directory via attrib', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Hidden File or Directory via attrib (DB)');

-- ── T1222.002 : setuid/setgid ビット付与(chmod)──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Setuid Setgid Permission Modification (DB)', 'sigma', ARRAY['linux','windows','macos'], 6,
$$title: Setuid Setgid Permission Modification (DB)
description: Detects chmod setting the setuid/setgid bit (u+s, 4755, ...) — privilege escalation and persistence.
status: experimental
level: medium
tags:
  - attack.t1222.002
  - attack.defense_evasion
  - attack.privilege_escalation
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains|all:
      - "chmod"
    CommandLine|contains:
      - " u+s"
      - " g+s"
      - " +s"
      - " 4755"
      - " 4777"
      - " 2755"
      - " 6755"
  condition: selection
falsepositives:
  - Package or build scripts setting setuid on legitimate binaries
$$,
'builtin-parity', ARRAY['T1222.002'],
'Two-engine parity: setuid/setgid permission modification via chmod', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Setuid Setgid Permission Modification (DB)');

-- ── T1070.003 : シェル履歴の消去/無効化 ──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Clear Command History (DB)', 'sigma', ARRAY['linux','windows','macos'], 5,
$$title: Clear Command History (DB)
description: Detects clearing/disabling of shell command history (history -c, unset HISTFILE, redirecting ~/.bash_history to /dev/null).
status: stable
level: medium
tags:
  - attack.t1070.003
  - attack.defense_evasion
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - "history -c"
      - "unset HISTFILE"
      - "HISTFILE=/dev/null"
      - "HISTSIZE=0"
      - "rm ~/.bash_history"
      - "rm -f ~/.bash_history"
      - "ln -sf /dev/null ~/.bash_history"
      - "truncate -s0 ~/.bash_history"
  condition: selection
falsepositives:
  - Rare; users seldom wipe history deliberately
$$,
'builtin-parity', ARRAY['T1070.003'],
'Two-engine parity: clear shell command history', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Clear Command History (DB)');
