-- 350: detection-server (DB RuleEngine) パリティ 第33弾 — ブラウザ/履歴認証情報・Pass-the-Hash。
--
-- api-server ビルトインにあるが DB 未移植の認証情報/横展開3種を移植する:
--   T1539     Steal Web Session Cookie   — ブラウザ Cookie/ログイン DB の読み取り/コピー
--   T1552.003 Bash History               — シェル/クライアント履歴ファイルの探索
--   T1550.002 Pass-the-Hash               — Invoke-TheHash/CME/NetExec/Impacket -hashes 等
-- ブラウザ DB は tool(Image)を CommandLine のコピー/読み取りツール語に置換。
-- 履歴・PtH はコマンドライン主体でそのまま移植する。
--
-- 備考: T1539 の Chrome `Network\Cookies` は YAML バックスラッシュ問題を避けるため
-- 除外し、"Login Data"/"cookies.sqlite"/"logins.json" 等の特徴的ファイル名で捕捉する。
--
-- platform は linux/windows/macos を明示。冪等化は WHERE NOT EXISTS。
-- 回帰は migration_rules_test.go 群 + migration_parity_test.go(発火)。

-- ── T1539 : ブラウザ Cookie/ログイン DB アクセス ──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Browser Cookie or Login Database Access (DB)', 'sigma', ARRAY['linux','windows','macos'], 7,
$$title: Browser Cookie or Login Database Access (DB)
description: Detects copying/reading a browser cookie/credential database (Chrome Login Data, Firefox cookies.sqlite/logins.json) to steal session tokens and saved passwords.
status: experimental
level: high
tags:
  - attack.t1539
  - attack.credential_access
logsource:
  category: process_creation
detection:
  store:
    CommandLine|contains:
      - "Login Data"
      - "cookies.sqlite"
      - "logins.json"
  tool:
    CommandLine|contains:
      - "copy"
      - "xcopy"
      - "robocopy"
      - "esentutl"
      - "sqlite3"
      - "cat "
      - "cp "
      - "type "
  condition: store and tool
falsepositives:
  - Backup software touching browser profiles
$$,
'builtin-parity', ARRAY['T1539'],
'Two-engine parity: browser cookie/login database access', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Browser Cookie or Login Database Access (DB)');

-- ── T1552.003 : シェル履歴からの認証情報探索 ──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Shell History Credential Search (DB)', 'sigma', ARRAY['linux','windows','macos'], 5,
$$title: Shell History Credential Search (DB)
description: Detects reading/searching shell and client history files (.bash_history, .mysql_history, ...) that often contain plaintext credentials.
status: stable
level: medium
tags:
  - attack.t1552.003
  - attack.credential_access
logsource:
  category: process_creation
detection:
  history_file:
    CommandLine|contains:
      - ".bash_history"
      - ".zsh_history"
      - ".sh_history"
      - ".mysql_history"
      - ".psql_history"
      - ".rediscli_history"
  condition: history_file
falsepositives:
  - A user legitimately inspecting their own shell history
$$,
'builtin-parity', ARRAY['T1552.003'],
'Two-engine parity: shell history credential search', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Shell History Credential Search (DB)');

-- ── T1550.002 : Pass-the-Hash ──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Pass-the-Hash (DB)', 'sigma', ARRAY['linux','windows','macos'], 8,
$$title: Pass-the-Hash (DB)
description: Detects pass-the-hash lateral movement — Invoke-TheHash, CrackMapExec/NetExec hash auth, Impacket -hashes, pth-winexe, mimikatz sekurlsa::pth.
status: stable
level: high
tags:
  - attack.t1550.002
  - attack.lateral_movement
  - attack.credential_access
logsource:
  category: process_creation
detection:
  mimikatz_pth:
    CommandLine|contains: "sekurlsa::pth"
  invoke_thehash:
    CommandLine|contains:
      - "Invoke-SMBExec"
      - "Invoke-WMIExec"
      - "Invoke-TheHash"
      - "Invoke-SMBClient"
  cme_hash:
    CommandLine|contains|all:
      - "crackmapexec"
      - "-H "
  netexec_hash:
    CommandLine|contains|all:
      - "nxc "
      - "-H "
  impacket_hashes:
    CommandLine|contains: "-hashes "
  pth_toolkit:
    CommandLine|contains:
      - "pth-winexe"
      - "pth-smbclient"
  condition: mimikatz_pth or invoke_thehash or cme_hash or netexec_hash or impacket_hashes or pth_toolkit
falsepositives:
  - Authorised red-team / lateral-movement assessments
$$,
'builtin-parity', ARRAY['T1550.002'],
'Two-engine parity: pass-the-hash lateral movement', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Pass-the-Hash (DB)');
