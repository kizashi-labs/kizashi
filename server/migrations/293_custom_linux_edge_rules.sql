-- Migration 293: エッジ技の精密検知を埋めるカスタム Linux Sigma ルール(6件)
--
-- V1#3 広域測定(26技, 2026-07-02)で「Tactic 止まり=精密検知なし」だった技のうち、
-- 既存ルールでカバーされていない6技に技術固有ルールを追加。既存プールを確認済み:
--   T1046 は nmap/masscan/pnscan 用のみ(ss/netstat 非対応)、T1070.006 は service ファイル
--   限定、T1548.003 は sudoers.d 改変のみ、T1201/T1614.001/T1562.001 はホスト用ルール不在。
--
-- 設計: 誤検知を抑えるため Image パス依存を避け、CommandLine の「バイナリ+具体フラグ」
-- 部分文字列で照合(recon 特有の稀な組合せに限定)。platform=linux(#356 ゲート対象)。
-- 冪等: ON CONFLICT DO NOTHING。

INSERT INTO rules (id, name, type, platform, severity, content, enabled, source, mitre_tags, curate_state, created_at)
VALUES
-- ── T1046 Network Service Discovery(ss/netstat による待受サービス列挙)──
('ed6e0001-0000-0000-0000-000000000046',
 'Network Service Discovery via ss or netstat (Linux)', 'sigma', ARRAY['linux'], 4,
$$title: Network Service Discovery via ss or netstat (Linux)
status: stable
description: Detects enumeration of listening network services via ss/netstat recon flag combinations.
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    CommandLine|contains:
      - 'ss -tulpn'
      - 'ss -tuln'
      - 'ss -lntp'
      - 'ss -plnt'
      - 'ss -antp'
      - 'ss -tlnp'
      - 'netstat -tulpn'
      - 'netstat -tuln'
      - 'netstat -plnt'
      - 'netstat -antp'
  condition: selection
falsepositives:
  - Network administration and monitoring scripts
level: low$$,
 true, 'custom', ARRAY['T1046'], 'enabled', NOW()),

-- ── T1548.003 Sudo 権限列挙(sudo -l)──
('ed6e0001-0000-0000-0000-001548003000',
 'Sudo Privilege Enumeration (Linux)', 'sigma', ARRAY['linux'], 5,
$$title: Sudo Privilege Enumeration (Linux)
status: stable
description: Detects enumeration of allowed sudo commands (sudo -l), common in privilege-escalation reconnaissance.
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    CommandLine|contains:
      - 'sudo -l'
      - 'sudo -n -l'
      - 'sudo --list'
      - 'sudo -ll'
  condition: selection
falsepositives:
  - Legitimate administrators checking their sudo rights
level: medium$$,
 true, 'custom', ARRAY['T1548.003'], 'enabled', NOW()),

-- ── T1201 Password Policy Discovery ──
('ed6e0001-0000-0000-0000-000000001201',
 'Password Policy Discovery (Linux)', 'sigma', ARRAY['linux'], 4,
$$title: Password Policy Discovery (Linux)
status: stable
description: Detects reading of the system password policy (login.defs / pwquality) or per-account aging (chage -l, passwd -S).
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    CommandLine|contains:
      - '/etc/login.defs'
      - '/etc/security/pwquality'
      - 'chage -l'
      - 'passwd -S'
      - 'passwd --status'
  condition: selection
falsepositives:
  - Configuration management reading password policy
level: low$$,
 true, 'custom', ARRAY['T1201'], 'enabled', NOW()),

-- ── T1614.001 System Location Discovery ──
('ed6e0001-0000-0000-0000-000001614001',
 'System Location and Timezone Discovery (Linux)', 'sigma', ARRAY['linux'], 3,
$$title: System Location and Timezone Discovery (Linux)
status: stable
description: Detects discovery of system timezone/locale, used to fingerprint the host's geographic location.
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    CommandLine|contains:
      - 'timedatectl'
      - '/etc/timezone'
      - '/etc/localtime'
  condition: selection
falsepositives:
  - Time synchronization tooling
level: low$$,
 true, 'custom', ARRAY['T1614.001'], 'enabled', NOW()),

-- ── T1562.001 Impair Defenses(セキュリティ機構の列挙/停止)──
('ed6e0001-0000-0000-0000-001562001000',
 'Security Tooling Enumeration or Tampering (Linux)', 'sigma', ARRAY['linux'], 6,
$$title: Security Tooling Enumeration or Tampering (Linux)
status: stable
description: Detects enumeration or disabling of host security controls (auditd, SELinux, firewall).
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    CommandLine|contains:
      - 'auditctl -l'
      - 'auditctl -s'
      - 'systemctl is-active auditd'
      - 'systemctl stop auditd'
      - 'systemctl disable auditd'
      - 'service auditd stop'
      - 'setenforce 0'
  condition: selection
falsepositives:
  - Security tooling health checks by monitoring agents
level: medium$$,
 true, 'custom', ARRAY['T1562.001'], 'enabled', NOW()),

-- ── T1070.006 Timestomp(touch による時刻改ざん)──
('ed6e0001-0000-0000-0000-001070006000',
 'Timestamp Manipulation via touch (Linux)', 'sigma', ARRAY['linux'], 5,
$$title: Timestamp Manipulation via touch (Linux)
status: stable
description: Detects timestomping — setting an arbitrary or reference file access/modify time via touch, to hide activity.
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    CommandLine|contains:
      - 'touch -t '
      - 'touch -d '
      - 'touch -r '
      - 'touch --date'
      - 'touch --reference'
  condition: selection
falsepositives:
  - Build systems normalizing timestamps
level: medium$$,
 true, 'custom', ARRAY['T1070.006'], 'enabled', NOW())

ON CONFLICT (id) DO NOTHING;
