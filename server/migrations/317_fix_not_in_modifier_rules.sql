-- 317: match時エラーで死蔵していた2ルールの是正 (T1571, T1048.003)。
--
-- 019_sigma_community_rules.sql の "Suspicious Outbound Connection on Non-Standard
-- Port" (T1571) と "FTP Data Exfiltration over Non-Standard Port" (T1048.003) は
-- `DestinationPort|not_in:` という非標準の Sigma 修飾子を使っていた。sigma-go は
-- `not_in` を知らず、評価のたびに "unknown modifier not_in" を返す。RuleEngine.Evaluate
-- は err を握りつぶす (`if err != nil || !matched { continue }`) ため、これらのルールは
-- コンパイルは通るのに一度も発火せず、エラーも表に出ない「match時死蔵」だった。
--
-- 標準 Sigma の否定はコンディション階層で表現する (selection and not filter)。除外
-- ポートを filter_std_ports セレクションに移し、`condition: selection and not
-- filter_std_ports` に書き換える。019 の原文も同時に修正済み。
-- migration_coverage_test.go の TestNoMigrationSigmaRuleErrorsAtMatch が回帰固定する。

UPDATE rules
SET content = $$title: Suspicious Outbound Connection on Non-Standard Port
id: a1b2c3d4-0005-0005-0005-000000000024
status: experimental
description: Detects outbound network connections from common system processes on unusual ports that may indicate C2 activity
references:
  - https://attack.mitre.org/techniques/T1571/
logsource:
  category: network_connection
  product: windows
detection:
  selection:
    Initiated: 'true'
    Image|endswith:
      - '\svchost.exe'
      - '\lsass.exe'
      - '\winlogon.exe'
      - '\explorer.exe'
  filter_std_ports:
    DestinationPort:
      - 80
      - 443
      - 445
      - 135
      - 139
      - 53
  condition: selection and not filter_std_ports
falsepositives:
  - Legitimate software using non-standard ports
level: medium$$,
    updated_at = NOW()
WHERE id = 'a1b2c3d4-0005-0005-0005-000000000024'
  AND type = 'sigma';

UPDATE rules
SET content = $$title: FTP Data Exfiltration over Non-Standard Port
id: a1b2c3d4-0008-0008-0008-000000000039
status: experimental
description: Detects potential data exfiltration via FTP protocol on non-standard ports
references:
  - https://attack.mitre.org/techniques/T1048.003/
logsource:
  category: network_connection
  product: windows
detection:
  selection:
    Image|endswith:
      - '\ftp.exe'
      - '\wftp.exe'
  filter_std_ports:
    DestinationPort:
      - 21
      - 22
  condition: selection and not filter_std_ports
falsepositives:
  - Legitimate use of non-standard FTP servers
level: high$$,
    updated_at = NOW()
WHERE id = 'a1b2c3d4-0008-0008-0008-000000000039'
  AND type = 'sigma';
