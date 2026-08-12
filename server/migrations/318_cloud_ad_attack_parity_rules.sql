-- 318: detection-server (DB RuleEngine) パリティ。
--
-- api-server のビルトイン SigmaEvaluator に本スプリントで拡充した高価値の
-- クラウド/AD 攻撃検知を、もう一方の検知エンジン(detection-server RuleEngine)にも
-- 移植する。両エンジンで被覆することで、片方のイベント経路しか通らない攻撃も捕捉できる。
--
-- 全ルールは CommandLine|contains のみで選択(RuleEngine の field mapping で解決可能=
-- 死蔵を避ける)。platform は linux/windows/macos を明示(クラウドCLI/Impacket 等は
-- クロスプラットフォーム。process_creation category-only なので実質ユニバーサル)。
-- 冪等化は WHERE NOT EXISTS。以後の回帰は migration_rules_test.go 群
-- (compile / match時err / field-support / coverage)が固定する。

-- ── 前提: rules.source に 'builtin-parity' を許可する ─────────
-- このバッチ(318〜356)は全ルールを source='builtin-parity' で INSERT する。
-- しかし rules_source_check(001 で作成 / 276 で再定義)はこの値を許可しておらず、
-- 制約違反で INSERT が ERROR → RunMigrations が失敗 → api-server が起動不能になる
-- (CHECK 違反は "無言 drop" ではなく HARD ERROR。migrate.go は os.Exit(1))。
-- パリティ移行の先頭(=最初に 'builtin-parity' を INSERT する 318)で制約を広げる。
-- 冪等(DROP IF EXISTS → ADD)。276 の許可集合を保持し 'builtin-parity' を追加。
-- 以後の回帰は migration_source_constraint_test.go の適合テストが固定する。
ALTER TABLE rules DROP CONSTRAINT IF EXISTS rules_source_check;
ALTER TABLE rules ADD CONSTRAINT rules_source_check
    CHECK (source = ANY (ARRAY[
        'community'::text,
        'custom'::text,
        'threat-intel'::text,
        'ai-generated'::text,
        'builtin'::text,
        'sigmahq'::text,
        'builtin-parity'::text
    ]));

-- ── T1526 : クラウドサービス/IAM 探索 ───────────────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Cloud Service and IAM Discovery (DB)', 'sigma', ARRAY['linux','windows','macos'], 6,
$$title: Cloud Service and IAM Discovery (DB)
description: Detects enumeration of cloud identity, organization, and service configuration via cloud CLIs (aws sts get-caller-identity, aws iam/organizations list, gcloud iam/projects list), a common first step after cloud credential compromise.
status: stable
level: medium
tags:
  - attack.t1526
  - attack.discovery
logsource:
  category: process_creation
detection:
  aws_identity:
    CommandLine|contains:
      - "sts get-caller-identity"
      - "iam list-users"
      - "iam list-roles"
      - "organizations list-accounts"
      - "organizations describe-organization"
  gcloud_identity:
    CommandLine|contains:
      - "iam service-accounts"
      - "projects get-iam-policy"
      - "organizations list"
  condition: aws_identity or gcloud_identity
falsepositives:
  - Cloud administrators or IaC tooling auditing identity and org structure
$$,
'builtin-parity', ARRAY['T1526'],
'Two-engine parity: cloud service/IAM discovery via cloud CLIs', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Cloud Service and IAM Discovery (DB)');

-- ── T1562.008 : クラウドログ改ざん(防御回避) ────────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Cloud Logging Tampering (DB)', 'sigma', ARRAY['linux','windows','macos'], 8,
$$title: Cloud Logging Tampering (DB)
description: Detects disabling or deleting cloud audit/threat logging to blind defenders (aws cloudtrail stop-logging/delete-trail, aws guardduty delete-detector, gcloud logging sinks delete), an early defense-evasion step after cloud compromise.
status: stable
level: high
tags:
  - attack.t1562.008
  - attack.defense_evasion
logsource:
  category: process_creation
detection:
  aws_trail:
    CommandLine|contains:
      - "cloudtrail stop-logging"
      - "cloudtrail delete-trail"
      - "guardduty delete-detector"
  gcloud_sink:
    CommandLine|contains|all:
      - "logging sinks"
      - "delete"
  condition: aws_trail or gcloud_sink
falsepositives:
  - Rare; cloud administrators decommissioning logging (should be change-controlled)
$$,
'builtin-parity', ARRAY['T1562.008'],
'Two-engine parity: cloud audit/threat logging tampering', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Cloud Logging Tampering (DB)');

-- ── T1087.002 : ドメインアカウント探索(cmdlet/LOLBin/ADSI) ──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Domain Account Discovery (DB)', 'sigma', ARRAY['linux','windows','macos'], 5,
$$title: Domain Account Discovery (DB)
description: Detects enumeration of Active Directory user accounts via net.exe, dsquery, PowerView/AD cmdlets, BloodHound/SharpHound, or direct ADSI/LDAP search (adsisearcher/DirectorySearcher), used to map targets before privilege escalation.
status: stable
level: medium
tags:
  - attack.t1087.002
  - attack.discovery
logsource:
  category: process_creation
detection:
  net_user_domain:
    CommandLine|contains|all:
      - "net"
      - " user "
      - "/domain"
  tools:
    CommandLine|contains:
      - "dsquery user"
      - "Get-ADUser"
      - "Get-DomainUser"
      - "Invoke-BloodHound"
      - "SharpHound"
      - "adsisearcher"
      - "DirectorySearcher"
  condition: net_user_domain or tools
falsepositives:
  - Help-desk or identity-management tooling enumerating directory users
$$,
'builtin-parity', ARRAY['T1087.002'],
'Two-engine parity: domain account discovery incl. ADSI/BloodHound', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Domain Account Discovery (DB)');

-- ── T1558.004 : AS-REP ロースト(PowerShell/Rubeus/Impacket) ─
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'AS-REP Roasting (DB)', 'sigma', ARRAY['linux','windows','macos'], 8,
$$title: AS-REP Roasting (DB)
description: Detects AS-REP roasting via PowerShell (Invoke-ASREPRoast/Get-ASREPHash), enumeration of pre-auth-disabled accounts (DONT_REQ_PREAUTH/PreauthNotRequired), or the Impacket GetNPUsers tool, yielding crackable AS-REP hashes without prior domain credentials.
status: stable
level: high
tags:
  - attack.t1558.004
  - attack.credential_access
logsource:
  category: process_creation
detection:
  tools:
    CommandLine|contains:
      - "Invoke-ASREPRoast"
      - "Get-ASREPHash"
      - "ASREPRoast"
      - "GetNPUsers"
      - "DONT_REQ_PREAUTH"
      - "PreauthNotRequired"
  condition: tools
falsepositives:
  - Authorised AD security assessments enumerating pre-auth settings
$$,
'builtin-parity', ARRAY['T1558.004'],
'Two-engine parity: AS-REP roasting incl. Impacket GetNPUsers', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'AS-REP Roasting (DB)');

-- ── T1649 : AD CS 証明書悪用(Certipy) ──────────────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'AD CS Certificate Abuse (DB)', 'sigma', ARRAY['linux','windows','macos'], 8,
$$title: AD CS Certificate Abuse (DB)
description: Detects Active Directory Certificate Services abuse via Certipy (requesting, forging, or relaying certificates for authentication and privilege escalation, ESC1-16), a common modern path to Domain Admin.
status: stable
level: high
tags:
  - attack.t1649
  - attack.credential_access
logsource:
  category: process_creation
detection:
  certipy:
    CommandLine|contains: "certipy"
  condition: certipy
falsepositives:
  - Authorised AD CS security assessments using Certipy
$$,
'builtin-parity', ARRAY['T1649'],
'Two-engine parity: AD CS certificate abuse via Certipy', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'AD CS Certificate Abuse (DB)');
