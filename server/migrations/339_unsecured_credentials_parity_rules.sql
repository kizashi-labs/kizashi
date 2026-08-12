-- 339: detection-server (DB RuleEngine) パリティ 第22弾 — 保護されていない認証情報探索(T1552 系)。
--
-- api-server ビルトインにあるが DB 未移植の Unsecured Credentials 3種を移植する:
--   T1552.001 Credentials In Files    — findstr/grep で password/secret を再帰探索
--   T1552.002 Credentials in Registry — reg query /f password / Get-ItemProperty
--   T1552.004 Private Keys            — id_rsa/.pem/.ppk 等の秘密鍵を再帰収集
-- いずれも「ツール/動作 + 認証情報キーワード(または鍵ファイル名)」の複合条件で、
-- ビルトインが Image を併用する箇所は CommandLine 中の語で代替アンカーする。
--
-- platform は linux/windows/macos を明示。冪等化は WHERE NOT EXISTS。
-- 回帰は migration_rules_test.go 群 + migration_parity_test.go(発火)。

-- ── T1552.001 : ファイル内認証情報探索(findstr/grep 再帰 × キーワード)──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Credentials In Files Search (DB)', 'sigma', ARRAY['linux','windows','macos'], 6,
$$title: Credentials In Files Search (DB)
description: Detects findstr/grep recursively searching files for password/credential keywords (unsecured-credentials discovery).
status: stable
level: medium
tags:
  - attack.t1552.001
  - attack.credential_access
  - attack.discovery
logsource:
  category: process_creation
detection:
  tool:
    CommandLine|contains:
      - "findstr"
      - "grep"
  keyword:
    CommandLine|contains:
      - "password"
      - "passwd"
      - "credential"
      - "secret"
      - "apikey"
      - "api_key"
      - "connectionstring"
  recursive:
    CommandLine|contains:
      - "/s"
      - "/si"
      - "-r"
      - "--recursive"
  condition: tool and keyword and recursive
falsepositives:
  - Administrators or developers legitimately searching configuration files
$$,
'builtin-parity', ARRAY['T1552.001'],
'Two-engine parity: credentials in files search (findstr/grep recursive)', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Credentials In Files Search (DB)');

-- ── T1552.002 : レジストリ内認証情報探索(reg query /f password / Get-ItemProperty)──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Registry Credential Hunting (DB)', 'sigma', ARRAY['linux','windows','macos'], 6,
$$title: Registry Credential Hunting (DB)
description: Detects reg query /f password or PowerShell Get-ItemProperty searching the registry for stored credentials.
status: stable
level: medium
tags:
  - attack.t1552.002
  - attack.credential_access
logsource:
  category: process_creation
detection:
  reg_search:
    CommandLine|contains|all:
      - "query"
      - "/f"
    CommandLine|contains:
      - "password"
      - "passwd"
      - "pwd"
      - "credential"
  ps_search:
    CommandLine|contains|all:
      - "Get-ItemProperty"
      - "password"
  condition: reg_search or ps_search
falsepositives:
  - Administrators auditing for plaintext passwords in the registry
$$,
'builtin-parity', ARRAY['T1552.002'],
'Two-engine parity: registry credential hunting (reg query /f password)', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Registry Credential Hunting (DB)');

-- ── T1552.004 : 秘密鍵ハーベスト(再帰探索 × 鍵ファイル名)──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Private Key Harvesting (DB)', 'sigma', ARRAY['linux','windows','macos'], 6,
$$title: Private Key Harvesting (DB)
description: Detects recursive search/collection of private key material (id_rsa, .ppk, .pem, .pfx) — unsecured-credentials harvesting.
status: stable
level: medium
tags:
  - attack.t1552.004
  - attack.credential_access
logsource:
  category: process_creation
detection:
  harvest:
    CommandLine|contains:
      - "dir /s"
      - "-recurse"
      - "Get-ChildItem"
      - "findstr"
      - "ls -r"
      - "find /"
  keyfile:
    CommandLine|contains:
      - "id_rsa"
      - "id_dsa"
      - "id_ecdsa"
      - ".ppk"
      - ".pem"
      - ".pfx"
  condition: harvest and keyfile
falsepositives:
  - DevOps/CI scripts inventorying certificates or keys
$$,
'builtin-parity', ARRAY['T1552.004'],
'Two-engine parity: private key harvesting (recursive search x key file)', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Private Key Harvesting (DB)');
