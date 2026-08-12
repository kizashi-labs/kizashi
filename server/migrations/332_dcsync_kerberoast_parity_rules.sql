-- 332: detection-server (DB RuleEngine) パリティ 第15弾 — DCSync / Kerberoasting 補完。
--
-- mig324/331 に続く AD 資格情報アクセスの高信号 2種を移植する。両者とも
-- api-server ビルトインにあるが DB 未移植だった:
--   T1003.006 DCSync   — ディレクトリ複製(DRSUAPI)悪用でハッシュを複製取得
--   T1558.003 Kerberoasting — SPN チケット要求→オフライン解析
-- ビルトインは Kerberoasting で Image|contains rubeus を併用するが、DB エンジンでは
-- ツール名(rubeus)+攻撃固有指標を CommandLine|contains で捕捉する(死蔵回避)。
--
-- platform は linux/windows/macos を明示。冪等化は WHERE NOT EXISTS。
-- 回帰は migration_rules_test.go 群 + migration_parity_test.go(発火)。

-- ── T1003.006 : DCSync(DRSUAPI 資格情報複製)──────────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'DCSync Credential Replication (DB)', 'sigma', ARRAY['linux','windows','macos'], 9,
$$title: DCSync Credential Replication (DB)
status: stable
level: critical
tags:
  - attack.t1003.006
  - attack.credential_access
logsource:
  category: process_creation
detection:
  dcsync:
    CommandLine|contains:
      - "lsadump::dcsync"
      - "/dcsync"
      - "Invoke-DCSync"
      - "-just-dc"
      - "--just-dc"
  condition: dcsync
falsepositives:
  - None expected; DCSync from a non-DC host is essentially always malicious
$$,
'builtin-parity', ARRAY['T1003.006'],
'Two-engine parity: DCSync (DRSUAPI) credential replication', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'DCSync Credential Replication (DB)');

-- ── T1558.003 : Kerberoasting(SPN チケット要求→解析)───────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Kerberoasting (DB)', 'sigma', ARRAY['linux','windows','macos'], 8,
$$title: Kerberoasting (DB)
status: stable
level: high
tags:
  - attack.t1558.003
  - attack.credential_access
logsource:
  category: process_creation
detection:
  kerberoast:
    CommandLine|contains:
      - "rubeus"
      - "kerberoast"
      - "asreproast"
      - "/tgtdeleg"
      - ".kirbi"
      - "GetUserSPNs"
  condition: kerberoast
falsepositives:
  - Authorised red-team / AD security assessments
$$,
'builtin-parity', ARRAY['T1558.003'],
'Two-engine parity: Kerberoasting (Rubeus/GetUserSPNs) SPN ticket abuse', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Kerberoasting (DB)');
