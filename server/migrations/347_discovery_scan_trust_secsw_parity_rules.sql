-- 347: detection-server (DB RuleEngine) パリティ 第30弾 — ディスカバリ第2弾(スキャン/信頼/防御列挙)。
--
-- mig340(リモートシステム/グループ/共有)に続き、api-server ビルトインにあるが
-- DB 未移植の列挙3種を移植する:
--   T1046     Network Service Scanning   — nmap/masscan/zmap/rustscan, nc -z
--   T1482     Domain Trust Discovery     — nltest /domain_trusts, Get-DomainTrust
--   T1518.001 Security Software Discovery — EDR/AV エージェント名の列挙
-- ビルトインは一部 Image を併用する。DB エンジンでは コマンドライン中の
-- ツール名/フラグ/対象名で捕捉する。
--
-- platform は linux/windows/macos を明示。冪等化は WHERE NOT EXISTS。
-- 回帰は migration_rules_test.go 群 + migration_parity_test.go(発火)。

-- ── T1046 : ネットワークサービススキャン ──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Network Service Scanning (DB)', 'sigma', ARRAY['linux','windows','macos'], 5,
$$title: Network Service Scanning (DB)
description: Detects active network service/port scanning (nmap/masscan/zmap/rustscan, nc -z) used for recon and lateral-movement targeting.
status: stable
level: medium
tags:
  - attack.t1046
  - attack.discovery
logsource:
  category: process_creation
detection:
  scanners:
    CommandLine|contains:
      - "nmap"
      - "masscan"
      - "zmap"
      - "rustscan"
  ncscan:
    CommandLine|contains|all:
      - "nc "
      - "-z"
  condition: scanners or ncscan
falsepositives:
  - Authorised vulnerability scanning / asset inventory
$$,
'builtin-parity', ARRAY['T1046'],
'Two-engine parity: network service scanning', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Network Service Scanning (DB)');

-- ── T1482 : ドメイン信頼列挙 ──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Domain Trust Discovery (DB)', 'sigma', ARRAY['linux','windows','macos'], 5,
$$title: Domain Trust Discovery (DB)
description: Detects enumeration of AD domain trusts (nltest /domain_trusts, dsquery trustedDomain, PowerView Get-DomainTrust) — precursor to cross-domain movement.
status: stable
level: medium
tags:
  - attack.t1482
  - attack.discovery
logsource:
  category: process_creation
detection:
  nltest_trust:
    CommandLine|contains:
      - "/domain_trusts"
      - "/trusted_domains"
  dsquery_trust:
    CommandLine|contains: "objectClass=trustedDomain"
  powerview_trust:
    CommandLine|contains:
      - "Get-ADTrust"
      - "Get-DomainTrust"
      - "Get-NetDomainTrust"
      - "GetAllTrustRelationships"
  condition: nltest_trust or dsquery_trust or powerview_trust
falsepositives:
  - Domain administrators auditing trust relationships
$$,
'builtin-parity', ARRAY['T1482'],
'Two-engine parity: domain trust discovery', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Domain Trust Discovery (DB)');

-- ── T1518.001 : セキュリティソフトウェア検出 ──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Security Software Discovery (DB)', 'sigma', ARRAY['linux','windows','macos'], 4,
$$title: Security Software Discovery (DB)
description: Detects enumeration of host EDR/AV/audit tooling by name — fingerprinting defenses before evasion.
status: stable
level: low
tags:
  - attack.t1518.001
  - attack.discovery
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - "falcon-sensor"
      - "crowdstrike"
      - "sentinelone"
      - "carbon-black"
      - "cbagent"
      - "osqueryd"
      - "clamscan"
      - "wazuh"
      - "ossec"
  condition: selection
falsepositives:
  - Monitoring agents performing self health-checks
$$,
'builtin-parity', ARRAY['T1518.001'],
'Two-engine parity: security software discovery', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Security Software Discovery (DB)');
