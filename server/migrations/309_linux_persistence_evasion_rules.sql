-- 309: Linux under-tested タクティクスの検知ギャップ埋め(能動計測 2026-07-06 由来)。
--
-- 検証EC2 Linux agent への安全バッテリ計測で、検知率 62.5% / Technique特定 18.8% と判明。
-- 可視性は 100%(テレメトリは出ている)だが、以下は「ルール欠落」で Telemetry / Tactic 止まり
-- だった。process テレメトリ(command_line / image_path)は捕捉済みのため、DB sigma ルールで
-- technique 特定まで引き上げる(307/308 と同じ migration-only 経路、イメージ再ビルド不要)。
--
--   T1543.002 systemd サービス永続化      : systemctl enable が Telemetry 止まり
--   T1053.003 cron 永続化                 : behavioral で Tactic 止まり → technique 付与
--   T1548.001 setuid バイナリ作成         : 汎用 /tmp 実行ルールで Tactic 止まり
--   T1222.002 過度に緩い chmod            : 同上
--   T1562.001 セキュリティ機構の無効化    : 同上
--   T1070.003 コマンド履歴の消去          : 同上
--   T1003.008 /etc/shadow 読取            : Private Key Harvesting で Tactic 止まり → 専用化
--
-- 対象外(注記): T1021.004(ssh 横展開)= 通常運用の ssh と区別困難で高FP、new-host 相関が要る。
--   T1548.003(sudo)/T1552.001(grep 資格情報)も高FPのため単独ルール化せず。
--   T1098.004(authorized_keys)/T1546.004(.bashrc)= file テレメトリが /home 未監視の
--   「センサー欠落」ゆえルールでは不可(eBPF file probe 拡張が別途必要)。
--
-- RuleEngine は platform ゲート(PR#356)で linux イベントにのみ評価。severity は自動隔離
-- しきい値(AUTO_ISOLATE_MIN_SEVERITY=9)未満に抑える。冪等化は WHERE NOT EXISTS。

-- ── T1543.002 : systemd サービス永続化 ──────────────────────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Linux systemd Service Persistence (systemctl enable)', 'sigma', ARRAY['linux'], 5,
$$
title: Linux systemd Service Persistence (systemctl enable)
description: Detects enabling a systemd unit (systemctl enable / --user enable), the canonical systemd persistence step (T1543.002). Benign during package installs, but attacker-created units enabled for boot persistence surface here.
status: stable
level: medium
tags:
  - attack.t1543.002
  - attack.persistence
logsource:
  product: linux
  category: process_creation
detection:
  systemctl:
    CommandLine|contains: systemctl
  enable:
    CommandLine|contains: ' enable'
  condition: systemctl and enable
falsepositives:
  - Package managers and administrators enabling legitimate services
$$,
'community', ARRAY['T1543.002'],
'Linux measurement gap-fill: systemd service enable persistence', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Linux systemd Service Persistence (systemctl enable)');

-- ── T1053.003 : cron 永続化 ─────────────────────────────────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Linux Cron Persistence (crontab install/edit)', 'sigma', ARRAY['linux'], 5,
$$
title: Linux Cron Persistence (crontab install/edit)
description: Detects installing a crontab from stdin (the "(crontab -l; echo job) | crontab -" append idiom), editing one (crontab -e), or writing into cron drop-in directories — common Linux persistence (T1053.003). Listing (crontab -l) alone does not match, so the benign case is excluded by matching the install signal directly rather than by filtering.
status: stable
level: medium
tags:
  - attack.t1053.003
  - attack.persistence
  - attack.execution
logsource:
  product: linux
  category: process_creation
detection:
  install_pipe:
    CommandLine|contains: '| crontab'
  install_edit:
    CommandLine|contains: 'crontab -e'
  crondir:
    CommandLine|contains:
      - /etc/cron.d/
      - /etc/cron.hourly
      - /etc/cron.daily
      - /var/spool/cron
  condition: install_pipe or install_edit or crondir
falsepositives:
  - Administrators or deployment tooling installing scheduled jobs
$$,
'community', ARRAY['T1053.003'],
'Linux measurement gap-fill: cron persistence technique attribution', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Linux Cron Persistence (crontab install/edit)');

-- ── T1548.001 : setuid/setgid バイナリ作成 ──────────────────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Linux Setuid/Setgid Binary Creation', 'sigma', ARRAY['linux'], 6,
$$
title: Linux Setuid/Setgid Binary Creation
description: Detects setting the setuid/setgid bit on a binary (chmod u+s / +s / 4xxx / 2xxx / 6xxx), a classic privilege-escalation setup (T1548.001) rarely seen outside package installation.
status: stable
level: high
tags:
  - attack.t1548.001
  - attack.privilege_escalation
  - attack.defense_evasion
logsource:
  product: linux
  category: process_creation
detection:
  chmod:
    CommandLine|contains: chmod
  suid:
    CommandLine|contains:
      - u+s
      - g+s
      - +s
      - ' 4755'
      - ' 4777'
      - ' 2755'
      - ' 6755'
      - ' 04755'
  condition: chmod and suid
falsepositives:
  - Package installation scripts setting setuid on legitimate helpers
$$,
'community', ARRAY['T1548.001'],
'Linux measurement gap-fill: setuid binary creation', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Linux Setuid/Setgid Binary Creation');

-- ── T1222.002 : 過度に緩い chmod ────────────────────────────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Linux Overly Permissive chmod (777/world-writable)', 'sigma', ARRAY['linux'], 3,
$$
title: Linux Overly Permissive chmod (777/world-writable)
description: Detects granting world read/write/execute permissions (chmod 777 / 666 / a+rwx), often used by attackers to drop or stage tooling in shared locations (T1222.002).
status: stable
level: low
tags:
  - attack.t1222.002
  - attack.defense_evasion
logsource:
  product: linux
  category: process_creation
detection:
  chmod:
    CommandLine|contains: chmod
  perms:
    CommandLine|contains:
      - ' 777'
      - ' 0777'
      - ' 666'
      - a+rwx
  condition: chmod and perms
falsepositives:
  - Sloppy deployment scripts that relax permissions
$$,
'community', ARRAY['T1222.002'],
'Linux measurement gap-fill: permissive chmod', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Linux Overly Permissive chmod (777/world-writable)');

-- ── T1562.001 : セキュリティ機構の無効化 ────────────────────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Linux Impair Defenses (disable auditd/SELinux/AppArmor/firewall)', 'sigma', ARRAY['linux'], 7,
$$
title: Linux Impair Defenses (disable auditd/SELinux/AppArmor/firewall)
description: Detects disabling host security controls — SELinux (setenforce 0), auditd (systemctl/service stop, auditctl -e 0), AppArmor (aa-disable/aa-complain, stop apparmor) or the firewall (ufw disable, iptables -F) — a hallmark of defense evasion (T1562.001).
status: stable
level: high
tags:
  - attack.t1562.001
  - attack.defense_evasion
logsource:
  product: linux
  category: process_creation
detection:
  disable:
    CommandLine|contains:
      - 'setenforce 0'
      - 'setenforce Permissive'
      - 'systemctl stop auditd'
      - 'systemctl disable auditd'
      - 'service auditd stop'
      - 'auditctl -e 0'
      - 'aa-disable'
      - 'aa-complain'
      - 'systemctl stop apparmor'
      - 'systemctl disable apparmor'
      - 'ufw disable'
      - 'iptables -F'
      - 'iptables --flush'
  condition: disable
falsepositives:
  - Rare legitimate maintenance; review context
$$,
'community', ARRAY['T1562.001'],
'Linux measurement gap-fill: impair defenses', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Linux Impair Defenses (disable auditd/SELinux/AppArmor/firewall)');

-- ── T1070.003 : コマンド履歴の消去 ──────────────────────────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Linux Clear Command History', 'sigma', ARRAY['linux'], 5,
$$
title: Linux Clear Command History
description: Detects clearing or neutralizing shell command history — deleting/truncating .bash_history or pointing HISTFILE at /dev/null — to hide interactive activity (T1070.003).
status: stable
level: medium
tags:
  - attack.t1070.003
  - attack.defense_evasion
logsource:
  product: linux
  category: process_creation
detection:
  histfile_target:
    CommandLine|contains: .bash_history
  clear_verb:
    CommandLine|contains:
      - 'rm '
      - truncate
      - '/dev/null'
      - 'cat /dev/null'
  histfile_env:
    CommandLine|contains:
      - 'unset HISTFILE'
      - 'HISTFILE=/dev/null'
      - 'HISTSIZE=0'
      - 'export HISTFILE='
  condition: (histfile_target and clear_verb) or histfile_env
falsepositives:
  - Users legitimately resetting their shell history (uncommon)
$$,
'community', ARRAY['T1070.003'],
'Linux measurement gap-fill: clear command history', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Linux Clear Command History');

-- ── T1003.008 : /etc/shadow 読取 ────────────────────────────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Linux /etc/shadow Credential Access', 'sigma', ARRAY['linux'], 7,
$$
title: Linux /etc/shadow Credential Access
description: Detects reading or copying /etc/shadow (or /etc/gshadow) — direct access to local password hashes for offline cracking (T1003.008).
status: stable
level: high
tags:
  - attack.t1003.008
  - attack.credential_access
logsource:
  product: linux
  category: process_creation
detection:
  shadow:
    CommandLine|contains:
      - /etc/shadow
      - /etc/gshadow
  reader:
    CommandLine|contains:
      - 'cat '
      - 'cp '
      - 'less '
      - 'more '
      - 'head '
      - 'tail '
      - 'unshadow'
      - 'base64 '
      - 'xxd '
      - 'nano '
      - 'vi '
      - 'vim '
      - 'awk '
      - 'cut '
  condition: shadow and reader
falsepositives:
  - Backup tooling reading /etc/shadow (rare; review context)
$$,
'community', ARRAY['T1003.008'],
'Linux measurement gap-fill: /etc/shadow credential access', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Linux /etc/shadow Credential Access');
