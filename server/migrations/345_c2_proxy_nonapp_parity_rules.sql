-- 345: detection-server (DB RuleEngine) パリティ 第28弾 — C2/プロキシ・非アプリ層プロトコル。
--
-- api-server ビルトインにあるが DB 未移植の C2 系3種を移植する:
--   T1090.001 Internal Proxy       — netsh portproxy add(侵害ホスト経由のピボット)
--   T1090.003 Multi-hop Proxy      — Tor クライアント実行 / .onion 参照
--   T1095     Non-Application Layer — netcat/ncat リバースシェル・ポートフォワード
-- ビルトインは Image を併用する。DB エンジンでは コマンドライン中のツール名 +
-- 攻撃固有フラグで捕捉する。netcat は bare "nc" の誤検知を避けるため、明示的な
-- ncat/netcat 名、または "nc " + リバースシェル/リッスンフラグの複合で捕捉する。
--
-- platform は linux/windows/macos を明示。冪等化は WHERE NOT EXISTS。
-- 回帰は migration_rules_test.go 群 + migration_parity_test.go(発火)。

-- ── T1090.001 : 内部プロキシ(netsh portproxy add)──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Internal Proxy via netsh portproxy (DB)', 'sigma', ARRAY['linux','windows','macos'], 7,
$$title: Internal Proxy via netsh portproxy (DB)
description: Detects creation of a netsh portproxy rule to relay/pivot traffic through a compromised host (C2 internal proxy).
status: stable
level: high
tags:
  - attack.t1090.001
  - attack.command_and_control
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains|all:
      - "netsh"
      - "portproxy"
      - "add"
  condition: selection
falsepositives:
  - Rare legitimate port-forwarding configured by administrators
$$,
'builtin-parity', ARRAY['T1090.001'],
'Two-engine parity: internal proxy via netsh portproxy', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Internal Proxy via netsh portproxy (DB)');

-- ── T1090.003 : マルチホッププロキシ(Tor / .onion)──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Tor Anonymity Client Execution (DB)', 'sigma', ARRAY['linux','windows','macos'], 6,
$$title: Tor Anonymity Client Execution (DB)
description: Detects execution of the Tor client or references to .onion services — anonymized C2/exfiltration.
status: stable
level: medium
tags:
  - attack.t1090.003
  - attack.command_and_control
logsource:
  category: process_creation
detection:
  onion:
    CommandLine|contains: ".onion"
  tor_binary:
    CommandLine|contains:
      - "tor.exe"
      - "tor-browser"
      - "torbrowser"
  condition: onion or tor_binary
falsepositives:
  - Privacy-conscious users intentionally running Tor
$$,
'builtin-parity', ARRAY['T1090.003'],
'Two-engine parity: Tor anonymity client / .onion', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Tor Anonymity Client Execution (DB)');

-- ── T1095 : 非アプリ層プロトコル(netcat/ncat リバースシェル)──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Netcat Reverse Shell or Relay (DB)', 'sigma', ARRAY['linux','windows','macos'], 7,
$$title: Netcat Reverse Shell or Relay (DB)
description: Detects netcat/ncat used for reverse shells or port forwarding — non-application-layer C2.
status: stable
level: high
tags:
  - attack.t1095
  - attack.command_and_control
logsource:
  category: process_creation
detection:
  explicit_tool:
    CommandLine|contains:
      - "ncat"
      - "netcat"
      - "nc.traditional"
  nc_flags:
    CommandLine|contains|all:
      - "nc "
    CommandLine|contains:
      - " -e "
      - " -e/"
      - "-lvp"
      - "-lnvp"
      - "-nvlp"
      - "-lp "
  condition: explicit_tool or nc_flags
falsepositives:
  - Authorised network debugging
$$,
'builtin-parity', ARRAY['T1095'],
'Two-engine parity: netcat reverse shell or relay', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Netcat Reverse Shell or Relay (DB)');
