-- 316: macOS 検知ギャップの補完（テレメトリはあるがルールが無い領域）。
--
-- 2026-07-12 の検知率深掘りで、macOS エージェントは完全なプロセス実行テレメトリ
-- (Image/CommandLine) を出しているのに、ATT&CK カバレッジ監査は Windows/Linux のみを
-- 対象としており macOS 固有ルールが乏しいことが判明。既存の macOS ルール
-- (AppleScript実行, LaunchAgent永続化, Keychain, Gatekeeperバイパス, Login Item,
--  screencapture, Login/Logoutフック, dscl隠しアカウント作成) と重複しない、
-- プロセス実行シグネチャで確実に発火するギャップを補完する。
--
-- すべて logsource product=macos / category=process_creation。platform=ARRAY['macos']
-- で OS ゲート対象（rule_engine.canonPlatform が darwin/macos を畳み込む）。
-- description にはコロン+スペースを含めない（migration 019 の YAML 死蔵の再発防止）。
-- 冪等: ON CONFLICT (id) DO NOTHING。

-- ── T1033 / T1082 — System & Owner/User Discovery (macOS) ──────────────
INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'f1a0c0de-0316-0001-0001-000000000001',
  'macOS System and Owner Discovery',
  'sigma',
  ARRAY['macos'],
  3,
  $SIGMA$title: macOS System and Owner Discovery
id: f1a0c0de-0316-0001-0001-000000000001
status: stable
description: Detects common macOS host and user reconnaissance commands often run early in an intrusion to profile the endpoint
references:
  - https://attack.mitre.org/techniques/T1082/
  - https://attack.mitre.org/techniques/T1033/
logsource:
  product: macos
  category: process_creation
detection:
  selection:
    Image|endswith:
      - /system_profiler
      - /sw_vers
      - /whoami
      - /id
      - /hostname
  condition: selection
falsepositives:
  - IT administrators running diagnostics
  - Inventory and management agents
level: low$SIGMA$,
  true,
  false,
  false,
  ARRAY['T1082', 'T1033'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

-- ── T1087.001 — Local Account Discovery via dscl / dscacheutil (macOS) ──
-- Distinct from the existing T1564.002 rule (which detects hidden-account
-- CREATION with `dscl ... create ... IsHidden`); this covers enumeration.
INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'f1a0c0de-0316-0002-0002-000000000002',
  'macOS Local Account Discovery via dscl',
  'sigma',
  ARRAY['macos'],
  3,
  $SIGMA$title: macOS Local Account Discovery via dscl
id: f1a0c0de-0316-0002-0002-000000000002
status: stable
description: Detects enumeration of local accounts and groups via dscl or dscacheutil during the discovery phase
references:
  - https://attack.mitre.org/techniques/T1087/001/
logsource:
  product: macos
  category: process_creation
detection:
  selection_dscl:
    Image|endswith: /dscl
    CommandLine|contains:
      - -list /Users
      - -list /Groups
      - -read /Users
  selection_dscacheutil:
    Image|endswith: /dscacheutil
    CommandLine|contains:
      - -q user
      - -q group
  condition: selection_dscl or selection_dscacheutil
falsepositives:
  - Directory and management tooling enumerating accounts
level: low$SIGMA$,
  true,
  false,
  false,
  ARRAY['T1087.001'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

-- ── T1059.004 — Unix Shell Reverse Shell (macOS) ──────────────────────
-- The equivalent Linux rule (migration 019, id ...000034) is platform-scoped
-- to linux; /dev/tcp bash and `nc -e` reverse shells are equally viable on
-- macOS but had no macOS-scoped rule. auto_isolate stays false to avoid FP on
-- legitimate network diagnostics, matching the Linux rule's posture.
INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'f1a0c0de-0316-0003-0003-000000000003',
  'macOS Reverse Shell via Shell or netcat',
  'sigma',
  ARRAY['macos'],
  9,
  $SIGMA$title: macOS Reverse Shell via Shell or netcat
id: f1a0c0de-0316-0003-0003-000000000003
status: stable
description: Detects common reverse shell techniques on macOS using bash or zsh /dev/tcp redirection or netcat command execution to establish a C2 channel
references:
  - https://attack.mitre.org/techniques/T1059/004/
logsource:
  product: macos
  category: process_creation
detection:
  selection_shell:
    CommandLine|contains:
      - /dev/tcp/
      - /dev/udp/
      - bash -i
      - zsh -i
  selection_nc:
    Image|contains: /nc
    CommandLine|contains:
      - -e /bin/bash
      - -e /bin/sh
      - -e /bin/zsh
  condition: selection_shell or selection_nc
falsepositives:
  - Network testing utilities
level: critical$SIGMA$,
  true,
  false,
  false,
  ARRAY['T1059.004'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

-- ── T1548.003 — Sudoers / sensitive credential file modification (macOS) ──
-- File-event rule: /etc/sudoers and /etc/passwd are FIM-watched on macOS
-- (fim_collector_darwin.go) but had no macOS-scoped detection. Mirrors the
-- Linux rule (migration 019, id ...000032). Depends on macOS FIM file_event
-- telemetry being enabled.
INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'f1a0c0de-0316-0004-0004-000000000004',
  'macOS Sudoers or Passwd Modification',
  'sigma',
  ARRAY['macos'],
  8,
  $SIGMA$title: macOS Sudoers or Passwd Modification
id: f1a0c0de-0316-0004-0004-000000000004
status: stable
description: Detects modification of sudoers or the local passwd database on macOS which may indicate privilege escalation or credential manipulation
references:
  - https://attack.mitre.org/techniques/T1548/003/
logsource:
  product: macos
  category: file_event
detection:
  selection:
    TargetFilename|contains:
      - /etc/sudoers
      - /etc/passwd
  condition: selection
falsepositives:
  - Legitimate administrative changes via visudo
level: high$SIGMA$,
  true,
  false,
  false,
  ARRAY['T1548.003'],
  NOW()
) ON CONFLICT (id) DO NOTHING;
