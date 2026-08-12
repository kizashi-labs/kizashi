-- Migration 240: Additional Linux Sigma rules for §2 validation coverage
-- Adds process_creation rules from the sigma_builtins corpus that cover common
-- Linux attacker techniques not yet represented in the rules table.
-- Idempotent: uses ON CONFLICT DO NOTHING.

-- ── T1140 – Base64 エンコードコマンド実行 ──────────────────────────────────

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'b2c3d4e5-0001-0001-0001-000000000101',
  'Base64 Obfuscation Command Execution (Linux)',
  'sigma',
  ARRAY['linux'],
  6,
  $$title: Base64 Obfuscation Command Execution (Linux)
id: b2c3d4e5-0001-0001-0001-000000000101
status: stable
description: Detects base64 decode piped to a shell, a common technique to execute obfuscated payloads on Linux.
references:
  - https://attack.mitre.org/techniques/T1140/
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    CommandLine|contains:
      - 'base64 -d'
      - 'base64 --decode'
      - '| base64 -d'
      - '| base64 --decode'
  condition: selection
falsepositives:
  - Legitimate deployment scripts that decode configuration blobs
level: medium$$,
  true,
  false,
  false,
  ARRAY['T1140', 'T1059.004'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

-- ── T1095 – Netcat 不審な通信 ────────────────────────────────────────────────

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'b2c3d4e5-0002-0002-0002-000000000102',
  'Netcat Suspicious Network Activity (Linux)',
  'sigma',
  ARRAY['linux'],
  7,
  $$title: Netcat Suspicious Network Activity (Linux)
id: b2c3d4e5-0002-0002-0002-000000000102
status: stable
description: Detects execution of nc/ncat/netcat which may indicate reverse shell establishment or unauthorised port forwarding.
references:
  - https://attack.mitre.org/techniques/T1095/
logsource:
  category: process_creation
  product: linux
detection:
  selection_image:
    Image|contains:
      - /nc
      - /ncat
      - /netcat
      - /nc.traditional
  condition: selection_image
falsepositives:
  - Authorised network debugging and connectivity testing
level: high$$,
  true,
  false,
  false,
  ARRAY['T1095', 'T1059.004'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

-- ── T1105 – curl/wget による /tmp へのファイルダウンロード ─────────────────

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'b2c3d4e5-0003-0003-0003-000000000103',
  'curl/wget Download to Temp Directory (Linux)',
  'sigma',
  ARRAY['linux'],
  6,
  $$title: curl/wget Download to Temp Directory (Linux)
id: b2c3d4e5-0003-0003-0003-000000000103
status: stable
description: Detects curl or wget saving files directly into world-writable temp directories, a pattern commonly used by malware droppers.
references:
  - https://attack.mitre.org/techniques/T1105/
logsource:
  category: process_creation
  product: linux
detection:
  selection_tool:
    Image|contains:
      - curl
      - wget
  selection_dest:
    CommandLine|contains:
      - /tmp/
      - /dev/shm/
      - /var/tmp/
  condition: selection_tool and selection_dest
falsepositives:
  - Legitimate software installation scripts that download to /tmp before install
level: medium$$,
  true,
  false,
  false,
  ARRAY['T1105', 'T1059.004'],
  NOW()
) ON CONFLICT (id) DO NOTHING;
