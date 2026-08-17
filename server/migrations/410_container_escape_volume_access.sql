-- 346: カバレッジ0だった「コンテナ→ホスト脱出(T1611)」と「直接ボリューム
-- アクセス(T1006)」の補完。いずれも process_creation の CommandLine で低FPに絞る。

-- ── T1611 : ホスト名前空間 / cgroup 経由のコンテナエスケープ ───────────
-- コンテナから nsenter で PID1(ホスト)の名前空間へ入る、cgroup release_agent を
-- 悪用してホストでコマンド実行、/proc/1/root 経由でホストFSに触る、はいずれも
-- 特権コンテナ脱出の典型手口。正規運用ではほぼ現れない。
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Container Escape to Host via Namespace or Cgroup', 'sigma', ARRAY['linux'], 8,
$SIGMA$
title: Container Escape to Host via Namespace or Cgroup
description: Detects container-to-host escape primitives — nsenter into PID 1's host namespaces, abuse of the cgroup release_agent/notify_on_release for host command execution, or reaching the host filesystem via /proc/1/root. These break the container boundary to run code on the node (T1611) and are essentially absent from normal workloads.
status: stable
level: high
tags:
  - attack.t1611
  - attack.privilege_escalation
  - attack.defense_evasion
logsource:
  category: process_creation
detection:
  nsenter_host:
    Image|endswith: /nsenter
    CommandLine|contains:
      - '--target 1 '
      - '-t 1 '
      - '--all --target 1'
  cgroup_escape:
    CommandLine|contains:
      - 'release_agent'
      - 'notify_on_release'
  host_root:
    CommandLine|contains: '/proc/1/root/'
  condition: nsenter_host or cgroup_escape or host_root
falsepositives:
  - Node management agents that legitimately nsenter into host namespaces (scope by host/fleet)
$SIGMA$,
'community', ARRAY['T1611'],
'Coverage gap fill: container-to-host escape (was uncovered)', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Container Escape to Host via Namespace or Cgroup');

-- ── T1006 : 直接ボリューム/生ディスクアクセス ─────────────────────────
-- ファイルシステムAPIを迂回して生ディスク(\\.\PhysicalDrive, /dev/sdX)を直接読むと、
-- ロック/権限/監視を回避して NTFS MFT や機密ファイルを抜ける(T1006)。
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Direct Raw Disk or Volume Access', 'sigma', ARRAY['windows','linux'], 6,
$SIGMA$
title: Direct Raw Disk or Volume Access
description: Detects direct access to a raw disk or volume, bypassing the filesystem API to evade locks/ACLs/monitoring and read NTFS MFT or otherwise-locked secrets (T1006). Windows \\.\PhysicalDrive / \\.\<vol> handles and esentutl raw copies, or Linux dd reading a raw block device (/dev/sd*, /dev/nvme*, /dev/mapper).
status: experimental
level: medium
tags:
  - attack.t1006
  - attack.defense_evasion
logsource:
  category: process_creation
detection:
  win_raw:
    CommandLine|contains:
      - '\\.\PhysicalDrive'
      - '\\.\C:'
      - '\\.\D:'
  win_esentutl:
    Image|endswith: \esentutl.exe
    CommandLine|contains:
      - ' /y'
      - ' /vss'
  linux_dd:
    Image|endswith: /dd
    CommandLine|contains:
      - 'if=/dev/sd'
      - 'if=/dev/nvme'
      - 'if=/dev/mapper'
      - 'if=/dev/vd'
  condition: win_raw or win_esentutl or linux_dd
falsepositives:
  - Legitimate disk imaging / backup / forensics tooling (scope by host and operator)
$SIGMA$,
'community', ARRAY['T1006'],
'Coverage gap fill: direct raw disk / volume access (was uncovered)', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Direct Raw Disk or Volume Access');
