-- 346: detection-server (DB RuleEngine) パリティ 第29弾 — Linux/macOS 認証情報ダンプ。
--
-- api-server ビルトインにあるが DB 未移植の *nix 認証情報ダンプ3種を移植する:
--   T1003.007 Proc Filesystem       — /proc/<pid>/mem・maps を dd/cat/gdb/gcore で読む
--   T1003.008 /etc/passwd and shadow — /etc/shadow の読み取り/コピー・unshadow
--   T1555.001 Keychain (macOS)       — security dump-keychain / find-*-password
-- ビルトインは Image を併用する。DB エンジンでは コマンドライン中のツール/対象語 +
-- 攻撃固有フラグの複合条件で捕捉する(いずれもパス/サブコマンドが特徴的で低FP)。
--
-- platform は linux/windows/macos を明示。冪等化は WHERE NOT EXISTS。
-- 回帰は migration_rules_test.go 群 + migration_parity_test.go(発火)。

-- ── T1003.007 : /proc メモリ経由の認証情報アクセス ──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Process Memory Credential Access via proc (DB)', 'sigma', ARRAY['linux','windows','macos'], 8,
$$title: Process Memory Credential Access via proc (DB)
description: Detects reading another process memory through /proc/<pid>/mem or maps with dd/cat/gdb/gcore — scraping credentials from memory.
status: stable
level: high
tags:
  - attack.t1003.007
  - attack.credential_access
logsource:
  category: process_creation
detection:
  reader:
    CommandLine|contains:
      - "dd "
      - "cat "
      - "gdb"
      - "gcore"
  proc_mem:
    CommandLine|contains: "/proc/"
  region:
    CommandLine|contains:
      - "/mem"
      - "/maps"
  condition: reader and proc_mem and region
falsepositives:
  - Debugging or memory-forensics tooling
$$,
'builtin-parity', ARRAY['T1003.007'],
'Two-engine parity: process memory credential access via /proc', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Process Memory Credential Access via proc (DB)');

-- ── T1003.008 : /etc/shadow 認証情報ダンプ ──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Linux Shadow File Credential Dump (DB)', 'sigma', ARRAY['linux','windows','macos'], 8,
$$title: Linux Shadow File Credential Dump (DB)
description: Detects reading/copying of /etc/shadow or unshadow combining passwd+shadow for offline cracking.
status: stable
level: high
tags:
  - attack.t1003.008
  - attack.credential_access
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - "cat /etc/shadow"
      - "cp /etc/shadow"
      - "/etc/shadow /tmp"
      - "unshadow"
      - "cat /etc/gshadow"
  condition: selection
falsepositives:
  - Authorised account-management tooling
$$,
'builtin-parity', ARRAY['T1003.008'],
'Two-engine parity: /etc/shadow credential dump', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Linux Shadow File Credential Dump (DB)');

-- ── T1555.001 : macOS Keychain 認証情報アクセス(security ツール)──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'macOS Keychain Credential Access (DB)', 'sigma', ARRAY['linux','windows','macos'], 8,
$$title: macOS Keychain Credential Access (DB)
description: Detects dumping/extracting credentials from the macOS keychain via the security tool.
status: stable
level: high
tags:
  - attack.t1555.001
  - attack.credential_access
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains|all:
      - "security"
    CommandLine|contains:
      - "dump-keychain"
      - "find-generic-password"
      - "find-internet-password"
  condition: selection
falsepositives:
  - Administrative credential retrieval
$$,
'builtin-parity', ARRAY['T1555.001'],
'Two-engine parity: macOS keychain credential access via security tool', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'macOS Keychain Credential Access (DB)');
