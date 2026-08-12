-- 340: detection-server (DB RuleEngine) パリティ 第23弾 — AD/ネットワーク偵察(ディスカバリ)。
--
-- 横展開の前段で頻出する AD/ネットワーク列挙3種を移植する(api-server ビルトインに
-- あるが DB 未移植):
--   T1018     Remote System Discovery       — nltest /dclist, net view /domain,
--                                             dsquery computer, PowerView Get-*Computer, ADSI
--   T1069.002 Domain Group Discovery        — net group /domain, dsquery group,
--                                             Get-ADGroupMember, 特権グループ名
--   T1135     Network Share Discovery       — net share, Get-SmbShare, Invoke-ShareFinder
-- ビルトインは複数選択の OR で広く捕捉する。DB エンジンも複数選択 + ネスト条件を
-- 解釈できるためそのまま移植する。ただし UNC `net view \\host` 判定は YAML の
-- バックスラッシュエスケープ問題を避けるため本移植から除外し(mig331 と同方針)、
-- 他の高信号トークンで捕捉する。
--
-- platform は linux/windows/macos を明示。冪等化は WHERE NOT EXISTS。
-- 回帰は migration_rules_test.go 群 + migration_parity_test.go(発火)。

-- ── T1018 : リモートシステム/DC 列挙 ──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Remote System Discovery (DB)', 'sigma', ARRAY['linux','windows','macos'], 5,
$$title: Remote System Discovery (DB)
description: Detects enumeration of remote hosts and domain controllers (nltest /dclist, net view /domain, dsquery computer, PowerView Get-*Computer, ADSI) to select lateral-movement targets.
status: stable
level: medium
tags:
  - attack.t1018
  - attack.discovery
logsource:
  category: process_creation
detection:
  nltest_dc:
    CommandLine|contains:
      - "/dclist"
      - "/dsgetdc"
  net_view_domain:
    CommandLine|contains|all:
      - "net view"
      - "/domain"
  net_view_all:
    CommandLine|contains: "net view /all"
  dsquery_computer:
    CommandLine|contains: "dsquery computer"
  powerview_computer:
    CommandLine|contains:
      - "Get-ADComputer"
      - "Get-DomainComputer"
      - "Get-NetComputer"
  adsi_computer:
    CommandLine|contains|all:
      - "DirectoryServices"
    CommandLine|contains:
      - "objectClass=computer"
      - "objectCategory=computer"
  adsi_computer2:
    CommandLine|contains|all:
      - "adsisearcher"
    CommandLine|contains:
      - "objectClass=computer"
      - "objectCategory=computer"
  condition: nltest_dc or net_view_domain or net_view_all or dsquery_computer or powerview_computer or adsi_computer or adsi_computer2
falsepositives:
  - Administrators enumerating domain hosts or locating domain controllers
$$,
'builtin-parity', ARRAY['T1018'],
'Two-engine parity: remote system and DC discovery', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Remote System Discovery (DB)');

-- ── T1069.002 : ドメイングループ列挙 ──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Domain Group Discovery (DB)', 'sigma', ARRAY['linux','windows','macos'], 5,
$$title: Domain Group Discovery (DB)
description: Detects enumeration of AD groups and privileged membership (net group /domain, Get-ADGroupMember, PowerView Get-DomainGroup, dsquery group) to locate Domain/Enterprise Admins.
status: stable
level: medium
tags:
  - attack.t1069.002
  - attack.discovery
logsource:
  category: process_creation
detection:
  net_group_domain:
    CommandLine|contains|all:
      - "net group"
      - "/domain"
  net_group_privileged:
    CommandLine|contains:
      - "domain admins"
      - "enterprise admins"
      - "domain controllers"
  dsquery_group:
    CommandLine|contains: "dsquery group"
  powerview_group:
    CommandLine|contains:
      - "Get-ADGroupMember"
      - "Get-DomainGroup"
      - "Get-NetGroupMember"
  adsi_group:
    CommandLine|contains|all:
      - "DirectoryServices"
    CommandLine|contains:
      - "objectClass=group"
      - "objectCategory=group"
  adsi_group2:
    CommandLine|contains|all:
      - "adsisearcher"
    CommandLine|contains:
      - "objectClass=group"
      - "objectCategory=group"
  condition: net_group_domain or net_group_privileged or dsquery_group or powerview_group or adsi_group or adsi_group2
falsepositives:
  - Administrators auditing privileged group membership
$$,
'builtin-parity', ARRAY['T1069.002'],
'Two-engine parity: domain group discovery', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Domain Group Discovery (DB)');

-- ── T1135 : ネットワーク共有列挙 ──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Network Share Discovery (DB)', 'sigma', ARRAY['linux','windows','macos'], 5,
$$title: Network Share Discovery (DB)
description: Detects enumeration of network shares (net share, Get-SmbShare, Get-WmiObject Win32_Share, PowerView Invoke-ShareFinder/Find-DomainShare) to locate data and footholds.
status: stable
level: medium
tags:
  - attack.t1135
  - attack.discovery
logsource:
  category: process_creation
detection:
  net_share:
    CommandLine|contains: "net share"
  smb_share_ps:
    CommandLine|contains:
      - "Get-SmbShare"
      - "Get-WmiObject Win32_Share"
      - "Get-CimInstance Win32_Share"
  powerview_share:
    CommandLine|contains:
      - "Invoke-ShareFinder"
      - "Find-DomainShare"
      - "Find-InterestingDomainShareFile"
  condition: net_share or smb_share_ps or powerview_share
falsepositives:
  - Administrators auditing share exposure
$$,
'builtin-parity', ARRAY['T1135'],
'Two-engine parity: network share discovery', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Network Share Discovery (DB)');
