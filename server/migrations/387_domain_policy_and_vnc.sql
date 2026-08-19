-- 321: Windows ドメイン系 & Lateral の残穴補完(T1484 / T1021.005)。
--
-- 実測再監査(2026-07-12)で Privilege Escalation / Lateral Movement の残穴として
-- 特定した T1484(ドメイン/GPO ポリシ改変)と T1021.005(VNC)を補完。既存で被覆済みの
-- T1563.002(tscon RDP セッションハイジャック, builtin)や既存 Lateral は対象外。
-- T1111(MFA 横取り)はエンドポイントテレメトリで信頼できる検知が困難なため見送り
-- (攻撃者インフラ側=AiTM プロキシで発生し、被害端末プロセスに現れない)。
--
-- description にコロン+スペースを含めない。冪等: ON CONFLICT (id) DO NOTHING。

-- ── T1484.001/.002 — Domain / Group Policy Modification ───────────────
INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'd0a10000-0321-0001-0001-000000000001',
  'Domain or Group Policy Modification',
  'sigma',
  ARRAY['windows'],
  8,
  $SIGMA$title: Domain or Group Policy Modification
id: d0a10000-0321-0001-0001-000000000001
status: stable
description: Detects modification of Group Policy or domain trust and directory objects via GroupPolicy cmdlets, PowerView domain-object tampering, SharpGPOAbuse, or netdom trust, used to escalate privileges or weaken security domain-wide
references:
  - https://attack.mitre.org/techniques/T1484/001/
  - https://attack.mitre.org/techniques/T1484/002/
logsource:
  product: windows
  category: process_creation
detection:
  gpo_cmdlets:
    CommandLine|contains:
      - Set-GPRegistryValue
      - Set-GPPrefRegistryValue
      - New-GPLink
      - Set-GPLink
      - New-GPO
  gpo_abuse:
    CommandLine|contains:
      - SharpGPOAbuse
      - Set-DomainObject
      - Add-DomainObjectAcl
      - Add-DomainGroupMember
  trust_mod:
    CommandLine|contains:
      - 'netdom trust'
      - New-ADTrust
  condition: gpo_cmdlets or gpo_abuse or trust_mod
falsepositives:
  - Legitimate Group Policy administration by domain admins
level: high$SIGMA$,
  true,
  false,
  false,
  ARRAY['T1484.001', 'T1484.002'],
  NOW()
) ON CONFLICT (id) DO NOTHING;

-- ── T1021.005 — Remote Access via VNC ─────────────────────────────────
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
