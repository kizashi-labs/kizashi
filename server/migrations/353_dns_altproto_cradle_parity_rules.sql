-- 353: detection-server (DB RuleEngine) パリティ 第36弾 — DNS/代替プロトコル C2・ダウンロードクレードル。
--
-- api-server ビルトインにあるが DB 未移植の C2/持ち出し3種を移植する:
--   T1071.004 DNS Tunneling/C2          — dnscat2/iodine/dns2tcp/DNSExfiltrator 等
--   T1048     Exfil Over Alt Protocol    — curl -T / wget --post-file / tftp put / IWR -InFile
--   T1071.001 Web Protocols (Cradle)     — PowerShell ダウンロードクレードル
-- ビルトインは一部 Image を併用する。DB エンジンでは コマンドライン中のツール名 +
-- 攻撃固有フラグ/メソッド語で捕捉する。
--
-- platform は linux/windows/macos を明示。冪等化は WHERE NOT EXISTS。
-- 回帰は migration_rules_test.go 群 + migration_parity_test.go(発火)。

-- ── T1071.004 : DNS トンネリング/C2 ──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'DNS Tunneling and C2 (DB)', 'sigma', ARRAY['linux','windows','macos'], 8,
$$title: DNS Tunneling and C2 (DB)
description: Detects DNS-based C2/exfiltration tooling (dnscat2, iodine, dns2tcp, dnsteal, DNSExfiltrator) smuggling data inside DNS queries.
status: stable
level: high
tags:
  - attack.t1071.004
  - attack.command_and_control
  - attack.exfiltration
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - "dnscat"
      - "iodine"
      - "dns2tcp"
      - "dnsteal"
      - "DNSExfiltrator"
      - "Invoke-DnsExfil"
  condition: selection
falsepositives:
  - Rare; the named tools are not used by legitimate software
$$,
'builtin-parity', ARRAY['T1071.004'],
'Two-engine parity: DNS tunneling and C2', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'DNS Tunneling and C2 (DB)');

-- ── T1048 : 代替プロトコル経由の持ち出し(アップロードツール)──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Exfiltration Over Alternative Protocol (DB)', 'sigma', ARRAY['linux','windows','macos'], 6,
$$title: Exfiltration Over Alternative Protocol (DB)
description: Detects file-upload invocations of transfer tools to a remote host (curl -T/--upload-file, wget --post-file, tftp put, Invoke-WebRequest -InFile).
status: experimental
level: medium
tags:
  - attack.t1048
  - attack.exfiltration
logsource:
  category: process_creation
detection:
  curl:
    CommandLine|contains|all:
      - "curl"
    CommandLine|contains:
      - " -T "
      - "--upload-file"
      - "--data-binary @"
      - "--data @"
  wget:
    CommandLine|contains|all:
      - "wget"
    CommandLine|contains:
      - "--post-file"
      - "--body-file"
  tftp:
    CommandLine|contains|all:
      - "tftp"
      - "put"
  psupload:
    CommandLine|contains|all:
      - "invoke-webrequest"
      - "-infile"
  condition: curl or wget or tftp or psupload
falsepositives:
  - Legitimate scripted uploads or backups using curl/wget
$$,
'builtin-parity', ARRAY['T1048'],
'Two-engine parity: exfiltration over alternative protocol', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Exfiltration Over Alternative Protocol (DB)');

-- ── T1071.001 : PowerShell ダウンロードクレードル ──
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'PowerShell Web Download Cradle (DB)', 'sigma', ARRAY['linux','windows','macos'], 7,
$$title: PowerShell Web Download Cradle (DB)
description: Detects PowerShell downloading and executing remote content (download cradle) via WebClient/Invoke-* methods.
status: stable
level: high
tags:
  - attack.t1071.001
  - attack.command_and_control
  - attack.execution
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - "downloadstring"
      - "downloadfile"
      - "downloaddata"
      - "net.webclient"
      - "invoke-restmethod"
      - "openread"
      - "start-bitstransfer"
  condition: selection
falsepositives:
  - Legitimate administrative scripts fetching resources
$$,
'builtin-parity', ARRAY['T1071.001'],
'Two-engine parity: PowerShell web download cradle', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'PowerShell Web Download Cradle (DB)');
