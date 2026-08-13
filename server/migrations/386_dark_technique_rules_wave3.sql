-- 386: #525 由来の未着地ルール（第 3 波 / macOS 9 件・複数 OS 5 件）
--
-- P4-12 の最終波。これで #525 の未着地 34 件のうち 33 件が戻り、残るのは
-- SID-History Added to Account (Security Event 4765/4766) の 1 件だけになる
-- （proto 変更が要るため。migration 384 のヘッダを参照）。
--
-- ルール本文は移設元から逐語で、id も変えていない。
--
-- ── 使うフィールドは 3 つだけ ──
--
--   CommandLine / Image   process イベント（10 件 / 7 件）
--   TargetFilename        file イベント（3 件）← ingestion/handler.go:1206 の "path"
--
-- ── ★ 監視パスを 1 つ足している ──
--
-- `macOS Sudoers or Passwd Modification` は /etc/sudoers と /etc/passwd を
-- TargetFilename で見るが、darwin/file_collector.go の既定監視パスは
-- /Users /tmp /var/tmp /Applications /Library/Launch{Agents,Daemons} で
-- **/etc を含んでいなかった**。フィールドは解決するのに値が永久に来ない状態で、
-- 第 1 波で 4765/4766 のルールを弾いたのと同じ形である。
--
-- ここでは弾かずに、収集側へ /etc を足した。Linux 側
-- (linux/file_collector.go) には最初から /etc が入っており、**非対称の是正**
-- として正当化できるためである（このルールの都合だけが理由ではない）。
--
-- 他の 2 件（LaunchAgent/Daemon plist、シェル起動ファイル）は既定の監視配下に
-- あるのでそのまま動く。
--
-- ── 残る制約: macOS のプロセス収集はポーリングである ──
--
-- 既定ビルドの darwin/process_collector.go は
-- `//go:build darwin && (!esf || !cgo)` の ps ポーリング実装で、**短命プロセスを
-- 取りこぼす**。CommandLine / Image を使う 10 件は inert ではないが感度は落ちる。
-- ESF ビルドの出荷は P4-3 が未対応のままなので、この波を入れても残る制約である。
--
-- 移設元ブランチ: fix/migration-323-additive-constraint @ cb9a94e9

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'c4ed0000-0319-0003-0003-000000000003',
  'Credential Harvesting from Shell or DB History',
  'sigma',
  ARRAY['linux', 'macos'],
  5,
  $SIGMA$title: Credential Harvesting from Shell or DB History
id: c4ed0000-0319-0003-0003-000000000003
status: experimental
description: Detects reading of shell or database history files (bash/zsh/mysql/psql/redis history) that frequently contain plaintext passwords, tokens, and connection strings pasted on the command line
references:
  - https://attack.mitre.org/techniques/T1552/003/
logsource:
  category: process_creation
detection:
  reader:
    CommandLine|contains:
      - cat
      - less
      - more
      - grep
      - head
      - tail
      - strings
  history_file:
    CommandLine|contains:
      - .bash_history
      - .zsh_history
      - .mysql_history
      - .psql_history
      - .rediscli_history
      - .dbshell
  condition: reader and history_file
falsepositives:
  - Users or admins legitimately inspecting their own history
level: medium$SIGMA$,
  true,
  false,
  false,
  ARRAY['T1552.003'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'e0f1c0de-0317-0001-0001-000000000001',
  'Exfiltration to Anonymous File-sharing or Paste Site',
  'sigma',
  ARRAY['linux', 'windows', 'macos'],
  7,
  $SIGMA$title: Exfiltration to Anonymous File-sharing or Paste Site
id: e0f1c0de-0317-0001-0001-000000000001
status: stable
description: Detects use of an upload-capable HTTP client to send data to a well-known anonymous file-sharing or paste service, a common low-infrastructure exfiltration channel
references:
  - https://attack.mitre.org/techniques/T1567/003/
logsource:
  category: process_creation
detection:
  tool:
    CommandLine|contains:
      - curl
      - wget
      - Invoke-WebRequest
      - Invoke-RestMethod
      - iwr
      - powershell
  service:
    CommandLine|contains:
      - transfer.sh
      - 0x0.st
      - file.io
      - ix.io
      - termbin.com
      - pastebin.com/api
      - controlc.com
      - oshi.at
      - anonfiles
      - gofile.io
      - temp.sh
  condition: tool and service
falsepositives:
  - Developers sharing non-sensitive snippets via a paste service
level: high$SIGMA$,
  true,
  false,
  false,
  ARRAY['T1567.003'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'e0f1c0de-0317-0002-0002-000000000002',
  'Exfiltration to Cloud Storage via Native CLI',
  'sigma',
  ARRAY['linux', 'windows', 'macos'],
  5,
  $SIGMA$title: Exfiltration to Cloud Storage via Native CLI
id: e0f1c0de-0317-0002-0002-000000000002
status: experimental
description: Detects file uploads to cloud object storage via the native provider CLIs (aws s3, gsutil, gcloud storage, az storage blob), an exfiltration channel that blends with legitimate DevOps traffic
references:
  - https://attack.mitre.org/techniques/T1567/002/
logsource:
  category: process_creation
detection:
  aws:
    CommandLine|contains|all:
      - aws
      - s3
    CommandLine|contains:
      - ' cp '
      - ' sync '
      - put-object
  gcp:
    CommandLine|contains:
      - 'gsutil cp'
      - 'gsutil -m cp'
      - 'gsutil rsync'
      - 'gcloud storage cp'
  azure:
    CommandLine|contains|all:
      - az storage blob
      - upload
  condition: aws or gcp or azure
falsepositives:
  - Legitimate backup, deployment, or data-pipeline jobs uploading to cloud storage
level: medium$SIGMA$,
  true,
  false,
  false,
  ARRAY['T1567.002'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'd0a10000-0321-0002-0002-000000000002',
  'Remote Access via VNC Server or Client',
  'sigma',
  ARRAY['windows', 'linux', 'macos'],
  5,
  $SIGMA$title: Remote Access via VNC Server or Client
id: d0a10000-0321-0002-0002-000000000002
status: experimental
description: Detects execution of VNC server or client software used for interactive remote access and lateral movement, including headless server modes attackers deploy for hands-on control
references:
  - https://attack.mitre.org/techniques/T1021/005/
logsource:
  category: process_creation
detection:
  vnc_windows:
    Image|endswith:
      - \winvnc.exe
      - \tvnserver.exe
      - \vncviewer.exe
      - \uvnc_service.exe
      - \winvnc4.exe
  vnc_unix:
    Image|endswith:
      - /x11vnc
      - /vncserver
      - /vncviewer
      - /tigervncserver
  vnc_flags:
    CommandLine|contains:
      - '-rfbport'
      - '-nopw'
      - 'x11vnc -display'
  condition: vnc_windows or vnc_unix or vnc_flags
falsepositives:
  - Legitimate IT remote-support sessions using VNC
level: medium$SIGMA$,
  true,
  false,
  false,
  ARRAY['T1021.005'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'f1a0c0de-0328-0002-0002-000000000002',
  'Unix System Shutdown or Reboot',
  'sigma',
  ARRAY['linux', 'macos'],
  3,
  $SIGMA$title: Unix System Shutdown or Reboot
id: f1a0c0de-0328-0002-0002-000000000002
status: stable
description: Detects system shutdown reboot poweroff and halt commands on Linux and macOS which may indicate a destructive action finalizing an intrusion
references:
  - https://attack.mitre.org/techniques/T1529/
logsource:
  product: linux
  category: process_creation
detection:
  sel_bin:
    Image|endswith:
      - /shutdown
      - /reboot
      - /poweroff
      - /halt
  sel_systemctl:
    Image|endswith: /systemctl
    CommandLine|contains:
      - reboot
      - poweroff
      - halt
  sel_init:
    Image|endswith:
      - /init
      - /telinit
    CommandLine|contains:
      - ' 0'
      - ' 6'
  condition: sel_bin or sel_systemctl or sel_init
falsepositives:
  - Administrators rebooting hosts for maintenance
level: low$SIGMA$,
  true,
  false,
  false,
  ARRAY['T1529'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'e0f1c0de-0317-0003-0003-000000000003',
  'macOS Data Exfiltration via curl or scp Upload',
  'sigma',
  ARRAY['macos'],
  7,
  $SIGMA$title: macOS Data Exfiltration via curl or scp Upload
id: e0f1c0de-0317-0003-0003-000000000003
status: stable
description: Detects file upload from macOS shells via curl multipart/upload-file or scp to a remote host, used to transfer collected or staged data over a C2 or web channel
references:
  - https://attack.mitre.org/techniques/T1041/
logsource:
  product: macos
  category: process_creation
detection:
  curl_tool:
    CommandLine|contains: curl
  curl_upload_flag:
    CommandLine|contains:
      - ' -F '
      - ' --form'
      - ' -T '
      - ' --upload-file'
      - ' --data-binary @'
      - ' -d @'
  scp_out:
    CommandLine|contains: 'scp '
  condition: (curl_tool and curl_upload_flag) or scp_out
falsepositives:
  - Legitimate upload or backup scripts using curl or scp
level: high$SIGMA$,
  true,
  false,
  false,
  ARRAY['T1041'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  '3ac05000-0320-0001-0001-000000000001',
  'macOS Disable System Integrity Protection or Firewall',
  'sigma',
  ARRAY['macos'],
  9,
  $SIGMA$title: macOS Disable System Integrity Protection or Firewall
id: 3ac05000-0320-0001-0001-000000000001
status: stable
description: Detects disabling of core macOS security controls — System Integrity Protection via csrutil, the application firewall via socketfilterfw, or boot-args tampering via nvram — a strong defense-evasion signal that precedes deeper compromise
references:
  - https://attack.mitre.org/techniques/T1562/001/
logsource:
  product: macos
  category: process_creation
detection:
  csrutil:
    Image|endswith: /csrutil
    CommandLine|contains:
      - disable
      - 'enable --without'
  firewall:
    Image|endswith: /socketfilterfw
    CommandLine|contains:
      - '--setglobalstate off'
      - '--setglobalstate 0'
  nvram_bootargs:
    Image|endswith: /nvram
    CommandLine|contains: boot-args
  condition: csrutil or firewall or nvram_bootargs
falsepositives:
  - Developers intentionally disabling SIP in a controlled environment (rare, high-signal)
level: critical$SIGMA$,
  true,
  false,
  false,
  ARRAY['T1562.001'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  '3ac05000-0320-0002-0002-000000000002',
  'macOS Kernel Extension Load',
  'sigma',
  ARRAY['macos'],
  7,
  $SIGMA$title: macOS Kernel Extension Load
id: 3ac05000-0320-0002-0002-000000000002
status: stable
description: Detects loading of a kernel extension via kextload, kextutil, or kmutil load, used for kernel-level persistence, rootkits, or privilege escalation on macOS
references:
  - https://attack.mitre.org/techniques/T1547/006/
logsource:
  product: macos
  category: process_creation
detection:
  kext:
    Image|endswith:
      - /kextload
      - /kextutil
  kmutil:
    Image|endswith: /kmutil
    CommandLine|contains: load
  condition: kext or kmutil
falsepositives:
  - Legitimate third-party kernel extensions (VPNs, virtualization) during install
level: high$SIGMA$,
  true,
  false,
  false,
  ARRAY['T1547.006'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  '3ac05000-0320-0004-0004-000000000004',
  'macOS Launch Agent or Daemon plist File Creation',
  'sigma',
  ARRAY['macos'],
  7,
  $SIGMA$title: macOS Launch Agent or Daemon plist File Creation
id: 3ac05000-0320-0004-0004-000000000004
status: stable
description: Detects creation or modification of a launchd property list under a LaunchAgents or LaunchDaemons directory, the most common macOS persistence mechanism, observed via file integrity monitoring
references:
  - https://attack.mitre.org/techniques/T1543/001/
  - https://attack.mitre.org/techniques/T1543/004/
logsource:
  product: macos
  category: file_event
detection:
  selection:
    TargetFilename|contains:
      - /Library/LaunchAgents/
      - /Library/LaunchDaemons/
    TargetFilename|endswith: .plist
  condition: selection
falsepositives:
  - Legitimate application installers registering a login-time helper
level: high$SIGMA$,
  true,
  false,
  false,
  ARRAY['T1543.001', 'T1543.004'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

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

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  '3ac05000-0320-0003-0003-000000000003',
  'macOS Security Software Discovery',
  'sigma',
  ARRAY['macos'],
  4,
  $SIGMA$title: macOS Security Software Discovery
id: 3ac05000-0320-0003-0003-000000000003
status: experimental
description: Detects enumeration of installed macOS security or EDR products and controls via process listing or status commands filtered for known vendor and control names, common reconnaissance before defense evasion
references:
  - https://attack.mitre.org/techniques/T1518/001/
logsource:
  product: macos
  category: process_creation
detection:
  tooling:
    Image|endswith:
      - /ps
      - /pgrep
      - /csrutil
      - /spctl
  products:
    CommandLine|contains:
      - LittleSnitch
      - CrowdStrike
      - falcon
      - SentinelOne
      - sentineld
      - CarbonBlack
      - santad
      - BlockBlock
      - KnockKnock
      - 'csrutil status'
      - 'spctl --status'
  condition: tooling and products
falsepositives:
  - Administrators auditing installed security tooling
level: low$SIGMA$,
  true,
  false,
  false,
  ARRAY['T1518.001'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  '3ac05000-0320-0005-0005-000000000005',
  'macOS Shell Startup File Modification',
  'sigma',
  ARRAY['macos'],
  6,
  $SIGMA$title: macOS Shell Startup File Modification
id: 3ac05000-0320-0005-0005-000000000005
status: stable
description: Detects modification of a shell startup file (zsh or bash profile/rc) that runs on every interactive login, a common macOS persistence and execution vector, observed via file integrity monitoring
references:
  - https://attack.mitre.org/techniques/T1546/004/
logsource:
  product: macos
  category: file_event
detection:
  selection:
    TargetFilename|endswith:
      - /.zshrc
      - /.zprofile
      - /.bash_profile
      - /.bashrc
      - /.profile
  condition: selection
falsepositives:
  - User or tooling editing their own shell configuration (e.g. package managers)
level: medium$SIGMA$,
  true,
  false,
  false,
  ARRAY['T1546.004'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

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
