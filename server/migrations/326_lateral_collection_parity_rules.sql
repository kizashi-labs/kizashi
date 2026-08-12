-- 326: detection-server (DB RuleEngine) パリティ 第9弾 — 横展開/収集。
--
-- api-server ビルトインにあるがDB未移植の横展開(DCOM/Pass-the-Ticket)・収集
-- (クリップボード/ローカルメールストア/音声キャプチャ)を移植し、両エンジンで被覆する。
-- ビルトインは Image|endswith を併用するが、DB エンジンでは固有トークン(COM ProgID/CLSID、
-- Kerberos チケット文字列、メールストア拡張子、録音API)を CommandLine|contains で捕捉する。
--
-- platform は linux/windows/macos を明示。冪等化は WHERE NOT EXISTS。
-- 回帰は migration_rules_test.go 群 + migration_parity_test.go(発火)。

-- ── T1021.003 : DCOM 横展開 ─────────────────────────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'DCOM Lateral Movement (DB)', 'sigma', ARRAY['linux','windows','macos'], 7,
$$title: DCOM Lateral Movement (DB)
description: Detects lateral movement via DCOM objects (MMC20.Application, ShellWindows, ShellBrowserWindow) or DDE, instantiated by CLSID/ProgID to execute code on a remote host through a trusted COM server.
status: stable
level: high
tags:
  - attack.t1021.003
  - attack.lateral_movement
logsource:
  category: process_creation
detection:
  com:
    CommandLine|contains:
      - "MMC20.Application"
      - "ShellWindows"
      - "ShellBrowserWindow"
      - "GetTypeFromProgID"
      - "9BA05972-F6A8-11CF"
      - "C08AFD90-F2A1-11D1"
  dde:
    CommandLine|contains: "DDEInitiate"
  condition: com or dde
falsepositives:
  - Rare legitimate administrative COM automation
$$,
'builtin-parity', ARRAY['T1021.003'],
'Two-engine parity: DCOM lateral movement', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'DCOM Lateral Movement (DB)');

-- ── T1550.003 : Pass-the-Ticket ──────────────────────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Pass-the-Ticket (DB)', 'sigma', ARRAY['linux','windows','macos'], 8,
$$title: Pass-the-Ticket (DB)
description: Detects Kerberos ticket injection/reuse (kerberos::ptt, .kirbi files, Rubeus /ptt or asktgt/tgtdeleg) used to authenticate as another principal without their password, a common lateral-movement technique.
status: stable
level: high
tags:
  - attack.t1550.003
  - attack.lateral_movement
  - attack.credential_access
logsource:
  category: process_creation
detection:
  ptt:
    CommandLine|contains:
      - "kerberos::ptt"
      - ".kirbi"
      - " /ptt"
      - "ptt /ticket"
      - "asktgt"
      - "tgtdeleg"
  condition: ptt
falsepositives:
  - Authorised red-team / AD security assessments
$$,
'builtin-parity', ARRAY['T1550.003'],
'Two-engine parity: Pass-the-Ticket (Kerberos ticket injection)', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Pass-the-Ticket (DB)');

-- ── T1115 : クリップボードデータ収集 ─────────────────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Clipboard Data Collection (DB)', 'sigma', ARRAY['linux','windows','macos'], 5,
$$title: Clipboard Data Collection (DB)
description: Detects programmatic reading of the clipboard (Get-Clipboard, System.Windows.Forms.Clipboard, Windows.Clipboard GetText), used to steal copied secrets such as passwords and cryptocurrency addresses.
status: stable
level: medium
tags:
  - attack.t1115
  - attack.collection
logsource:
  category: process_creation
detection:
  clip:
    CommandLine|contains:
      - "Get-Clipboard"
      - "System.Windows.Forms.Clipboard"
      - "Windows.Clipboard]::GetText"
  condition: clip
falsepositives:
  - Clipboard-manager utilities or legitimate automation reading the clipboard
$$,
'builtin-parity', ARRAY['T1115'],
'Two-engine parity: clipboard data collection', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Clipboard Data Collection (DB)');

-- ── T1114.001 : ローカルメールストア収集 ────────────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Local Email Store Collection (DB)', 'sigma', ARRAY['linux','windows','macos'], 6,
$$title: Local Email Store Collection (DB)
description: Detects access to local email stores (Outlook .pst/.ost, Unix .mbox, Outlook Files directory) for mailbox theft, a common collection step before exfiltration.
status: stable
level: medium
tags:
  - attack.t1114.001
  - attack.collection
logsource:
  category: process_creation
detection:
  mailstore:
    CommandLine|contains:
      - ".pst"
      - ".ost"
      - ".mbox"
      - "Outlook Files"
  condition: mailstore
falsepositives:
  - Backup or migration tooling copying mail stores
$$,
'builtin-parity', ARRAY['T1114.001'],
'Two-engine parity: local email store collection', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Local Email Store Collection (DB)');

-- ── T1123 : 音声キャプチャ ──────────────────────────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Audio Capture (DB)', 'sigma', ARRAY['linux','windows','macos'], 6,
$$title: Audio Capture (DB)
description: Detects microphone/audio capture via recording APIs (waveInOpen, Get-AudioDevice, Windows.Media.Capture) or ffmpeg with an audio input device, used to eavesdrop on a target.
status: stable
level: medium
tags:
  - attack.t1123
  - attack.collection
logsource:
  category: process_creation
detection:
  api:
    CommandLine|contains:
      - "waveInOpen"
      - "Get-AudioDevice"
      - "Windows.Media.Capture"
  ffmpeg:
    CommandLine|contains|all:
      - "ffmpeg"
      - "audio="
  condition: api or ffmpeg
falsepositives:
  - Legitimate audio/conferencing software
$$,
'builtin-parity', ARRAY['T1123'],
'Two-engine parity: audio capture / eavesdropping', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Audio Capture (DB)');
