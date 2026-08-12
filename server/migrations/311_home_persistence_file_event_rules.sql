-- 311: /home 永続化ファイル書き込みの technique 特定(FIM /home 拡張の server 側補完)。
--
-- agent の FIM コレクタ(SHA-256 ポーリング)は #423 で /home 各ユーザーの永続化
-- パス(authorized_keys / shell-rc / systemd-user / autostart)を監視するよう拡張
-- され、さらに本ブランチで cron ドロップイン・/etc/rc.local・/etc/ld.so.preload・
-- /etc/profile.d を追加した。これらの書き込みが file_event として届くようになる。
--
-- authorized_keys(T1098.004)は既存 builtin(file_event)で発火するため、本 migration
-- では builtin に無い file_event ルールを補い、センサーが送るイベントを technique
-- 特定まで引き上げる:
--   T1546.004 シェル初期化ファイル改ざん(.bashrc/.profile/.zshrc/profile.d)
--   T1574.006 動的リンカ preload ハイジャック(/etc/ld.so.preload)
--   T1037.004 rc.local ブート永続化
--   T1053.003 cron ドロップインへのファイル作成(process_creation 版=309 の補完)
--
-- file_event の path は path→TargetFilename/FilePath, change_type→Operation に alias される
-- (handler.go / rule_engine.go)。RuleEngine は platform ゲートで linux イベントにのみ評価。
-- severity は自動隔離しきい値(AUTO_ISOLATE_MIN_SEVERITY=9)未満。冪等化は WHERE NOT EXISTS。
-- FP 抑制: .bashrc 等は正規編集でも modified が出るため level:medium/severity 5 に留める。
-- ld.so.preload は正規環境にほぼ存在しない高シグナルゆえ severity 7。

-- ── T1546.004 : シェル初期化ファイル改ざん(file_event) ───────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Linux Shell Init File Modification (FIM)', 'sigma', ARRAY['linux'], 5,
$$
title: Linux Shell Init File Modification (FIM)
description: Detects creation or modification of a user shell-init file (.bashrc/.bash_profile/.bash_login/.profile/.zshrc or /etc/profile.d) observed directly by file integrity monitoring. These files are sourced on every interactive login/shell, making them a common persistence and triggered-execution vector (T1546.004). Complements the process_creation rule that catches the "echo >> .bashrc / tee" idiom by also catching writes that never appear on a monitored command line.
status: stable
level: medium
tags:
  - attack.t1546.004
  - attack.persistence
  - attack.privilege_escalation
logsource:
  product: linux
  category: file_event
detection:
  selection:
    TargetFilename|contains:
      - /.bashrc
      - /.bash_profile
      - /.bash_login
      - /.profile
      - /.zshrc
      - /etc/profile.d/
  condition: selection
falsepositives:
  - Users legitimately editing their shell rc files
  - Package managers writing /etc/profile.d drop-ins
$$,
'community', ARRAY['T1546.004'],
'FIM sensor gap-fill: shell init file persistence via file_event', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Linux Shell Init File Modification (FIM)');

-- ── T1574.006 : 動的リンカ preload ハイジャック(file_event) ──────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Linux ld.so.preload Hijack (FIM)', 'sigma', ARRAY['linux'], 7,
$$
title: Linux ld.so.preload Hijack (FIM)
description: Detects creation or modification of /etc/ld.so.preload — the global dynamic-linker preload list that forces a shared object into every dynamically-linked process. It is almost never present on a normal host, so any write is a strong signal of a userland-rootkit persistence/defense-evasion primitive (T1574.006).
status: stable
level: high
tags:
  - attack.t1574.006
  - attack.persistence
  - attack.defense_evasion
logsource:
  product: linux
  category: file_event
detection:
  selection:
    TargetFilename|endswith: /etc/ld.so.preload
  condition: selection
falsepositives:
  - Rare legitimate use of LD_PRELOAD frameworks (review the injected object)
$$,
'community', ARRAY['T1574.006'],
'FIM sensor gap-fill: ld.so.preload dynamic-linker hijack', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Linux ld.so.preload Hijack (FIM)');

-- ── T1037.004 : rc.local ブート永続化(file_event) ───────────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Linux rc.local Boot Persistence (FIM)', 'sigma', ARRAY['linux'], 6,
$$
title: Linux rc.local Boot Persistence (FIM)
description: Detects creation or modification of /etc/rc.local, a script executed at boot by the rc-local compatibility unit — a classic Linux boot-persistence mechanism (T1037.004). Observed directly via file integrity monitoring so writes that bypass a monitored command line are still caught.
status: stable
level: medium
tags:
  - attack.t1037.004
  - attack.persistence
logsource:
  product: linux
  category: file_event
detection:
  selection:
    TargetFilename|endswith: /etc/rc.local
  condition: selection
falsepositives:
  - Administrators legitimately adding boot-time commands
$$,
'community', ARRAY['T1037.004'],
'FIM sensor gap-fill: rc.local boot persistence via file_event', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Linux rc.local Boot Persistence (FIM)');

-- ── T1053.003 : cron ドロップインへのファイル作成(file_event) ────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Linux Cron Drop-in File Written (FIM)', 'sigma', ARRAY['linux'], 5,
$$
title: Linux Cron Drop-in File Written (FIM)
description: Detects a file created or modified in a cron drop-in directory (/etc/cron.d, /etc/cron.{hourly,daily,weekly,monthly}) or a per-user crontab under /var/spool/cron, observed directly by file integrity monitoring — a common Linux scheduled-task persistence path (T1053.003). Complements the process_creation crontab rule.
status: stable
level: medium
tags:
  - attack.t1053.003
  - attack.persistence
  - attack.execution
logsource:
  product: linux
  category: file_event
detection:
  selection:
    TargetFilename|contains:
      - /etc/cron.d/
      - /etc/cron.hourly/
      - /etc/cron.daily/
      - /etc/cron.weekly/
      - /etc/cron.monthly/
      - /var/spool/cron/
  condition: selection
falsepositives:
  - Package managers or deployment tooling installing scheduled jobs
$$,
'community', ARRAY['T1053.003'],
'FIM sensor gap-fill: cron drop-in file persistence via file_event', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Linux Cron Drop-in File Written (FIM)');
