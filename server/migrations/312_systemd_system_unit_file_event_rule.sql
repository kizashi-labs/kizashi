-- 312: システムレベル systemd ユニット作成/改ざんの technique 特定(FIM 補完)。
--
-- #423/#426(migration 311)は /home 各ユーザーの systemd-user、および cron/
-- ld.so.preload/rc.local/profile.d の file_event を補完したが、**システムレベルの
-- systemd**(/etc/systemd/system)は死角のまま残っていた。ここに .service を落とす、
-- または .d/ ドロップインで既存ユニットを上書きするのは root 権限での常套的な永続化
-- (T1543.002)であり、user systemd(~/.config/systemd/user)とは別面。
--
-- 本 migration とペアで agent の FIM コレクタに /etc/systemd/system(再帰)監視を追加
-- している(fim_collector_linux.go)。既存 T1543.002 ルールは process_creation
-- (systemd-run 等のコマンドライン)のみを見るため、ユニットファイルを直接書く経路は
-- この file_event ルールが担う。
--
-- file_event の path は path→TargetFilename/FilePath に alias される。RuleEngine は
-- platform ゲートで linux イベントにのみ評価。severity は自動隔離しきい値
-- (AUTO_ISOLATE_MIN_SEVERITY=9)未満。冪等化は WHERE NOT EXISTS。
-- FP 抑制: パッケージインストールでもユニットは作成されるため level:medium/severity 5。

INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Linux systemd System Unit Persistence (FIM)', 'sigma', ARRAY['linux'], 5,
$$
title: Linux systemd System Unit Persistence (FIM)
description: Detects creation or modification of a unit under /etc/systemd/system — a dropped .service or a .d/ drop-in override that runs as root at boot. Complements the process_creation systemd-run rule by catching direct unit-file writes surfaced via FIM (T1543.002).
status: stable
level: medium
tags:
  - attack.t1543.002
  - attack.persistence
  - attack.privilege_escalation
logsource:
  product: linux
  category: file_event
detection:
  selection:
    TargetFilename|contains: /etc/systemd/system/
  condition: selection
falsepositives:
  - Package installation / legitimate service provisioning (ansible, dpkg, rpm)
$$,
'community', ARRAY['T1543.002'],
'FIM sensor gap-fill: system-level systemd unit persistence', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Linux systemd System Unit Persistence (FIM)');
