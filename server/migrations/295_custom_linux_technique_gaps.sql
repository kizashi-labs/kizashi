-- Migration 295: Technique 精密検知の残ギャップを埋めるカスタム Linux Sigma ルール(4件)
--
-- 2026-07-02 の修正後 live 再計測(docs/results/live-20260702-linux-postfix-scorecard.md)で
-- 「Tactic 止まり=精密検知なし」だった技に技術固有ルールを追加し、解析検知(Technique)を
-- 100% に到達させる。検証EC2 の実 process イベント(image 空・command_line のみ記録)に
-- 合わせ CommandLine 部分文字列で照合。platform=linux(#356 ゲート対象)、冪等。
--
-- 対象と根拠(実測 command_line):
--   T1204.002  "/bin/sh /tmp/edr_v4_.../x.sh"            → temp ディレクトリからのスクリプト実行
--   T1546.004  "sed -i /edr-test-marker/d /root/.bashrc" → シェル rc 改変
--   T1048      "curl ... -X POST --data exfil=x ..."     → curl/wget での POST 持ち出し
--   T1518.001  "which ... falcon-sensor osqueryd clamscan" → セキュリティ製品の探索

INSERT INTO rules (id, name, type, platform, severity, content, enabled, source, mitre_tags, curate_state, created_at)
VALUES
-- ── T1204.002 User Execution: Malicious File(world-writable ディレクトリからの実行)──
('ed6e0002-0000-0000-0000-001204002000',
 'Script Execution from World-Writable Directory (Linux)', 'sigma', ARRAY['linux'], 4,
$$title: Script Execution from World-Writable Directory (Linux)
status: stable
description: Detects execution of a shell script from a world-writable temp directory (/tmp, /dev/shm, /var/tmp), a common User Execution vector for downloaded payloads.
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    CommandLine|contains:
      - 'sh /tmp/'
      - 'sh /dev/shm/'
      - 'sh /var/tmp/'
      - 'bash /tmp/'
      - 'bash /dev/shm/'
      - 'bash /var/tmp/'
  condition: selection
falsepositives:
  - Package installers and build systems running helper scripts from temp
level: low$$,
 true, 'custom', ARRAY['T1204.002'], 'enabled', NOW()),

-- ── T1546.004 Event Triggered Execution: Unix Shell Configuration Modification ──
('ed6e0002-0000-0000-0000-001546004000',
 'Shell Startup File Modification (Linux)', 'sigma', ARRAY['linux'], 4,
$$title: Shell Startup File Modification (Linux)
status: stable
description: Detects modification of shell startup files (.bashrc/.bash_profile/.profile/.zshrc, /etc/profile) used for persistence via shell configuration.
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    CommandLine|contains:
      - '.bashrc'
      - '.bash_profile'
      - '.bash_login'
      - '.profile'
      - '.zshrc'
      - '/etc/profile'
      - '/etc/bash.bashrc'
  condition: selection
falsepositives:
  - Legitimate provisioning that edits shell rc files
level: low$$,
 true, 'custom', ARRAY['T1546.004'], 'enabled', NOW()),

-- ── T1048 Exfiltration Over Alternative Protocol(curl/wget での POST 持ち出し)──
('ed6e0002-0000-0000-0000-000000001048',
 'Data Exfiltration via curl/wget POST (Linux)', 'sigma', ARRAY['linux'], 5,
$$title: Data Exfiltration via curl/wget POST (Linux)
status: stable
description: Detects outbound HTTP POST with an inline data body via curl/wget, a common ad-hoc exfiltration channel.
logsource:
  category: process_creation
  product: linux
detection:
  tool:
    CommandLine|contains:
      - 'curl'
      - 'wget'
  method:
    CommandLine|contains:
      - '-X POST'
      - '--request POST'
      - '--data'
      - '--data-binary'
      - '--post-data'
      - '--post-file'
  condition: tool and method
falsepositives:
  - Application/API automation that legitimately POSTs data
level: medium$$,
 true, 'custom', ARRAY['T1048'], 'enabled', NOW()),

-- ── T1518.001 Security Software Discovery(EDR/AV 製品の探索)──
('ed6e0002-0000-0000-0000-001518001000',
 'Security Software Discovery (Linux)', 'sigma', ARRAY['linux'], 4,
$$title: Security Software Discovery (Linux)
status: stable
description: Detects enumeration of host security products (EDR/AV/audit) by name via which/ps/grep, used to fingerprint defenses.
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    CommandLine|contains:
      - 'falcon-sensor'
      - 'osqueryd'
      - 'clamscan'
      - 'crowdstrike'
      - 'carbon-black'
      - 'cbagent'
      - 'sentinelone'
      - 'sentinel-agent'
      - 'wazuh'
      - 'ossec'
  condition: selection
falsepositives:
  - Security tooling health checks by monitoring agents
level: low$$,
 true, 'custom', ARRAY['T1518.001'], 'enabled', NOW())

ON CONFLICT (id) DO NOTHING;
