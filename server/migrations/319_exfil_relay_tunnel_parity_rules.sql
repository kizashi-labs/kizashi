-- 319: detection-server (DB RuleEngine) パリティ 第2弾。
--
-- 本スプリントで api-server のビルトイン SigmaEvaluator に追加した「持ち出し/
-- 認証リレー/トンネリング」系の高価値・低誤検知技法を、もう一方の検知エンジン
-- (detection-server RuleEngine)へ移植する。ビルトイン側は Image|contains を併用
-- しているが、DB エンジンの field mapping で確実に解決できる CommandLine|contains
-- のみで等価に表現する(死蔵回避)。ツール名/固有サブコマンドが必ずコマンドライン
-- に現れる技法だけを選抜しているため、Image 依存を外しても検知力は維持される。
--
-- platform は linux/windows/macos を明示(rclone/Responder/ntlmrelayx/Impacket/
-- chisel 等はクロスプラットフォーム)。冪等化は WHERE NOT EXISTS。以後の回帰は
-- migration_rules_test.go 群 (compile / match時err / field-support / coverage) と
-- migration_parity_test.go (発火) が固定する。

-- ── T1567.002 : クラウドストレージへの持ち出し(rclone/MEGAcmd) ─
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Exfiltration to Cloud Storage (DB)', 'sigma', ARRAY['linux','windows','macos'], 8,
$$title: Exfiltration to Cloud Storage (DB)
description: Detects rclone or MEGAcmd copying/syncing data to cloud storage backends (rclone copy/sync with transfer flags, MEGAcmd/mega-put/megatools), the dominant exfiltration tooling in ransomware intrusions. Keys on command-line syntax so a renamed rclone binary is still caught.
status: stable
level: high
tags:
  - attack.t1567.002
  - attack.exfiltration
logsource:
  category: process_creation
detection:
  rclone_cmd:
    CommandLine|contains|all:
      - "rclone"
    CommandLine|contains:
      - "copy"
      - "sync"
      - ":b2"
      - ":s3"
      - "--transfers"
      - "--multi-thread"
  mega_tools:
    CommandLine|contains:
      - "megatools"
      - "mega-put"
      - "MEGAcmd"
      - "mega-cmd"
      - "megacmdserver"
  condition: rclone_cmd or mega_tools
falsepositives:
  - Sanctioned backup workflows that use rclone or MEGA
$$,
'builtin-parity', ARRAY['T1567.002'],
'Two-engine parity: cloud-storage exfiltration via rclone/MEGAcmd', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Exfiltration to Cloud Storage (DB)');

-- ── T1557.001 : LLMNR/NBT-NS ポイズニング & NTLM リレー ──────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'LLMNR NBT-NS Poisoning and NTLM Relay (DB)', 'sigma', ARRAY['linux','windows','macos'], 8,
$$title: LLMNR NBT-NS Poisoning and NTLM Relay (DB)
description: Detects LLMNR/NBT-NS/mDNS poisoning and NTLM credential-relay tooling (Responder, Inveigh, Impacket ntlmrelayx, mitm6) used to capture NetNTLM hashes and relay authentication on the local network, a common first foothold in AD intrusions.
status: stable
level: high
tags:
  - attack.t1557.001
  - attack.credential_access
logsource:
  category: process_creation
detection:
  tools:
    CommandLine|contains:
      - "Invoke-Inveigh"
      - "Inveigh.ps1"
      - "Inveigh.exe"
      - "responder.py"
      - "Responder.py"
      - "ntlmrelayx"
      - "mitm6"
  condition: tools
falsepositives:
  - Authorised network security assessments
$$,
'builtin-parity', ARRAY['T1557.001'],
'Two-engine parity: LLMNR/NBT-NS poisoning and NTLM relay tooling', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'LLMNR NBT-NS Poisoning and NTLM Relay (DB)');

-- ── T1558.001 : ゴールデン/シルバーチケット偽造 ───────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Golden or Silver Ticket Forging (DB)', 'sigma', ARRAY['linux','windows','macos'], 9,
$$title: Golden or Silver Ticket Forging (DB)
description: Detects Kerberos golden/silver ticket forging via Rubeus golden/silver subcommands, Impacket ticketer, or krbtgt/service hash injection (kerberos::golden, /krbtgt:), used for durable domain persistence and privilege escalation to Domain Admin.
status: stable
level: critical
tags:
  - attack.t1558.001
  - attack.credential_access
logsource:
  category: process_creation
detection:
  rubeus_golden:
    CommandLine|contains|all:
      - "rubeus"
      - "golden"
  rubeus_silver:
    CommandLine|contains|all:
      - "rubeus"
      - "silver"
  krbtgt_hash:
    CommandLine|contains:
      - "/krbtgt:"
      - "kerberos::golden"
  impacket_ticketer:
    CommandLine|contains:
      - "ticketer.py"
      - "ticketer "
  condition: rubeus_golden or rubeus_silver or krbtgt_hash or impacket_ticketer
falsepositives:
  - Authorised AD security assessments forging test tickets
$$,
'builtin-parity', ARRAY['T1558.001'],
'Two-engine parity: golden/silver ticket forging (Rubeus/Impacket)', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Golden or Silver Ticket Forging (DB)');

-- ── T1572 : プロトコルトンネリング(ngrok/chisel/frp/plink) ────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Protocol Tunneling Tool Execution (DB)', 'sigma', ARRAY['linux','windows','macos'], 6,
$$title: Protocol Tunneling Tool Execution (DB)
description: Detects known tunneling/port-forwarding utilities (ngrok, chisel client/server, frp frpc/frps, plink reverse/local/dynamic forwarding) used for C2 or network pivoting to reach otherwise unreachable internal hosts.
status: stable
level: medium
tags:
  - attack.t1572
  - attack.command_and_control
logsource:
  category: process_creation
detection:
  ngrok:
    CommandLine|contains: "ngrok"
  chisel:
    CommandLine|contains|all:
      - "chisel"
    CommandLine|contains:
      - "client"
      - "server"
  frp:
    CommandLine|contains:
      - "frpc"
      - "frps"
  plink:
    CommandLine|contains|all:
      - "plink"
    CommandLine|contains:
      - " -R"
      - " -L"
      - " -D"
  condition: ngrok or chisel or frp or plink
falsepositives:
  - Authorised remote-access or debugging tunnels
$$,
'builtin-parity', ARRAY['T1572'],
'Two-engine parity: protocol tunneling tools (ngrok/chisel/frp/plink)', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Protocol Tunneling Tool Execution (DB)');
