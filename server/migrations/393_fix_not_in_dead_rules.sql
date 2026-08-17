-- 329: not_in / not_startswith を使う死蔵ルール3件を標準 Sigma へ書き換え。
--
-- 2026-07-13 の2エンジン差分調査で判明: `field|not_in` / `field|not_startswith` は
-- 標準 Sigma のモディファイアではなく、RuleEngine が使う外部 sigma-go では
-- 「コンパイルは通るが評価で常に非マッチ」＝**本番(rules 表→RuleEngine 経路)で完全死蔵**
-- していた。以前セッションで自前 SigmaEvaluator 側に not_in を実装したが、これら3ルールは
-- migration 019(rules 表)にあり本番では sigma-go が評価するため、その修正は本番に効かず、
-- テストが誤って自前評価器で検証していたため見逃されていた(テスト忠実性の穴)。
--
-- 対応: 否定を標準 Sigma の `selection and not filter` イディオムへ書き換え。両エンジンで
-- 同一挙動になる(engine_parity_test / rule_engine 側の発火テストで固定)。019 ソースも同修正。
-- 全文置換で冪等。
--   - a1b2c3d4-...024  Suspicious Outbound Connection on Non-Standard Port (T1571)
--   - a1b2c3d4-...039  FTP Data Exfiltration over Non-Standard Port (T1048.003)
--   - a1b2c3d4-...042  Kerberoasting via Rubeus or Impacket (T1558.003)

-- (1) T1571 Suspicious Outbound: not_in → filter_common_ports。
UPDATE rules
SET content = $SIGMA$title: Suspicious Outbound Connection on Non-Standard Port
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
  filter_common_ports:
    DestinationPort:
      - 80
      - 443
      - 445
      - 135
      - 139
      - 53
  condition: selection and not filter_common_ports
falsepositives:
  - Legitimate software using non-standard ports
level: medium$SIGMA$,
    updated_at = NOW()
WHERE id = 'a1b2c3d4-0005-0005-0005-000000000024';

-- (2) T1048.003 FTP Exfiltration: not_in → filter_standard_ports。
UPDATE rules
SET content = $SIGMA$title: FTP Data Exfiltration over Non-Standard Port
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
  filter_standard_ports:
    DestinationPort:
      - 21
      - 22
  condition: selection and not filter_standard_ports
falsepositives:
  - Legitimate use of non-standard FTP servers
level: high$SIGMA$,
    updated_at = NOW()
WHERE id = 'a1b2c3d4-0008-0008-0008-000000000039';

-- (3) T1558.003 Kerberoasting: not_startswith → filter_machine_account。
UPDATE rules
SET content = $SIGMA$title: Kerberoasting via Rubeus or Impacket
id: a1b2c3d4-0009-0009-0009-000000000042
status: stable
description: Detects Kerberoasting attacks via known tools like Rubeus or Impacket targeting service account credentials
references:
  - https://attack.mitre.org/techniques/T1558.003/
logsource:
  category: process_creation
  product: windows
detection:
  selection_rubeus:
    CommandLine|contains:
      - 'rubeus'
      - 'kerberoast'
      - 'asreproast'
  selection_event:
    EventID: 4769
    TicketEncryptionType: '0x17'
  filter_machine_account:
    ServiceName|startswith: '$'
  condition: selection_rubeus or (selection_event and not filter_machine_account)
falsepositives:
  - Legitimate Kerberos service ticket requests
level: critical$SIGMA$,
    updated_at = NOW()
WHERE id = 'a1b2c3d4-0009-0009-0009-000000000042';
