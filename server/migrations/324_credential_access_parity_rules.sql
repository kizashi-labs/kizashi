-- 324: detection-server (DB RuleEngine) パリティ 第7弾 — 認証情報アクセス。
--
-- EDR 最重要戦術。api-server ビルトインにあるがDB未移植の cmdline 検知可能な資格情報窃取を
-- detection-server RuleEngine へ移植し、両エンジンで被覆する。ビルトインは Image|contains を
-- 併用するが、DB エンジンでは固有ツール名・フラグ・レジストリハイブ名を CommandLine|contains で
-- 捕捉する(死蔵回避)。contains は大文字小文字を区別しない。
--
-- platform は linux/windows/macos を明示。冪等化は WHERE NOT EXISTS。
-- 回帰は migration_rules_test.go 群 + migration_parity_test.go(発火)。

-- ── T1003.003 : NTDS.dit 抽出(AD DB オフライン窃取) ──────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'NTDS.dit Extraction (DB)', 'sigma', ARRAY['linux','windows','macos'], 9,
$$title: NTDS.dit Extraction (DB)
description: Detects extraction of the Active Directory database (NTDS.dit) for offline credential theft via ntdsutil IFM/create full or direct reference to the ntds.dit file.
status: stable
level: critical
tags:
  - attack.t1003.003
  - attack.credential_access
logsource:
  category: process_creation
detection:
  ntdsutil:
    CommandLine|contains|all:
      - "ntdsutil"
    CommandLine|contains:
      - "ifm"
      - "create full"
  ntdsdit:
    CommandLine|contains: "ntds.dit"
  condition: ntdsutil or ntdsdit
falsepositives:
  - Authorised domain controller backups
$$,
'builtin-parity', ARRAY['T1003.003'],
'Two-engine parity: NTDS.dit AD database extraction', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'NTDS.dit Extraction (DB)');

-- ── T1003.004 : LSA Secrets ダンプ ───────────────────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'LSA Secrets Dump (DB)', 'sigma', ARRAY['linux','windows','macos'], 8,
$$title: LSA Secrets Dump (DB)
description: Detects dumping of LSA secrets (service account passwords, cached secrets) via saving the HKLM\SECURITY registry hive or mimikatz lsadump::secrets, for offline credential extraction.
status: stable
level: high
tags:
  - attack.t1003.004
  - attack.credential_access
logsource:
  category: process_creation
detection:
  reg_save:
    CommandLine|contains|all:
      - "save"
      - "HKLM"
      - "SECURITY"
  lsadump_secrets:
    CommandLine|contains: "lsadump::secrets"
  condition: reg_save or lsadump_secrets
falsepositives:
  - Rare legitimate backup of registry hives
$$,
'builtin-parity', ARRAY['T1003.004'],
'Two-engine parity: LSA secrets dump (SECURITY hive / lsadump)', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'LSA Secrets Dump (DB)');

-- ── T1003.005 : キャッシュされたドメイン資格情報(DCC2) ────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Cached Domain Credentials Dump (DB)', 'sigma', ARRAY['linux','windows','macos'], 8,
$$title: Cached Domain Credentials Dump (DB)
description: Detects tools/commands that extract MSCache/DCC2 cached domain credentials (cachedump, gsecdump, mimikatz lsadump::cache), crackable offline for domain passwords.
status: stable
level: high
tags:
  - attack.t1003.005
  - attack.credential_access
logsource:
  category: process_creation
detection:
  tools:
    CommandLine|contains:
      - "cachedump"
      - "gsecdump"
      - "lsadump::cache"
  condition: tools
falsepositives:
  - None expected
$$,
'builtin-parity', ARRAY['T1003.005'],
'Two-engine parity: cached domain credentials (DCC2) dump', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Cached Domain Credentials Dump (DB)');

-- ── T1552.006 : Group Policy Preferences パスワード ──────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Group Policy Preferences Password (DB)', 'sigma', ARRAY['linux','windows','macos'], 8,
$$title: Group Policy Preferences Password (DB)
description: Detects retrieval of Group Policy Preferences credentials by searching SYSVOL for the cpassword attribute or running Get-GPPPassword, which yields AES-decryptable domain passwords.
status: stable
level: high
tags:
  - attack.t1552.006
  - attack.credential_access
logsource:
  category: process_creation
detection:
  gpp:
    CommandLine|contains:
      - "cpassword"
      - "Get-GPPPassword"
  condition: gpp
falsepositives:
  - Rare legitimate GPP auditing
$$,
'builtin-parity', ARRAY['T1552.006'],
'Two-engine parity: Group Policy Preferences password retrieval', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Group Policy Preferences Password (DB)');

-- ── T1555.004 : Windows 資格情報マネージャ ───────────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Windows Credential Manager Access (DB)', 'sigma', ARRAY['linux','windows','macos'], 6,
$$title: Windows Credential Manager Access (DB)
description: Detects enumeration/harvesting of stored credentials via cmdkey /list or vaultcmd /list, used to pull cached credentials from the Windows Credential Manager / vault.
status: stable
level: medium
tags:
  - attack.t1555.004
  - attack.credential_access
logsource:
  category: process_creation
detection:
  cmdkey:
    CommandLine|contains|all:
      - "cmdkey"
      - "/list"
  vaultcmd:
    CommandLine|contains|all:
      - "vaultcmd"
    CommandLine|contains:
      - "/list"
      - "/listcreds"
  condition: cmdkey or vaultcmd
falsepositives:
  - Administrators auditing stored credentials
$$,
'builtin-parity', ARRAY['T1555.004'],
'Two-engine parity: Windows Credential Manager harvesting', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Windows Credential Manager Access (DB)');
