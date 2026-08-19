-- 378: allow 'tamper' in events.event_type, and seed the DB-side detection rules.
--
-- The agent gained a userland self-protection path: the watchdog records deaths
-- it did not ask for, and the agent periodically re-checks its own binary and
-- config against an in-memory baseline and the liveness of its supervisor. Those
-- findings ship as "tamper:<uuid>:<json>" (EVENT_TYPE_LOG), and promoteEventType
-- (internal/ingestion/handler.go) resolves them to "tamper".
--
-- Without this migration that resolution is exactly the failure 373 documents:
-- publishEventBatch persists first and publishes second, so the DB write is
-- rejected with 23514 while the NATS publish still happens. Detection would fire
-- but the events table would hold no trace of the very events that say someone is
-- trying to disable the agent — and the multi-row INSERT would degrade to 501
-- round trips for every batch containing one.
--
-- Same additive shape as 370/373: read the current definition and append, so a
-- deployment whose constraint already carries out-of-tree values keeps them.
--
-- ★ NOT VALID を付ける（2026-08-12）。この移行は制約を**検証付き**で張っており、
-- events に「新しいリストに無い型」の行が1件でもあると ALTER が失敗する。API は起動時に
-- マイグレーションを流して失敗で終了するため、結果は機能の劣化ではなく**再起動ループ**で、
-- 以降の移行が一切適用されなくなる（2026-08-03 に実際に発生し、数日間 20 本以上のルール
-- 移行が適用されないまま運用されていた）。
--
-- そうした行は実在する。制約はどこかの時点で NOT VALID で張られており、それ以前の行は
-- 検証されていないため、ブランチを跨いで更新された配備は現行のどの移行も知らない値を
-- 持ちうる。制約は「これから書かれるもの」を守るためのもので、過去について主張しない。
-- 検査は internal/store/migration_legacy_rows_test.go。

DO $migration$
DECLARE
  cur_def  text;
  arr_body text;
BEGIN
  SELECT pg_get_constraintdef(c.oid) INTO cur_def
    FROM pg_constraint c
   WHERE c.conname = 'events_event_type_check'
     AND c.conrelid = 'events'::regclass
   LIMIT 1;

  -- Already permitted (re-run, or an out-of-tree branch added it): nothing to do.
  IF cur_def IS NOT NULL AND position('''tamper''' in cur_def) > 0 THEN
    RETURN;
  END IF;

  -- No constraint at all: create one from the known base set.
  IF cur_def IS NULL THEN
    ALTER TABLE events
      ADD CONSTRAINT events_event_type_check
        CHECK (event_type = ANY (ARRAY[
          'process', 'file', 'network', 'dns', 'registry', 'auth', 'process_stats',
          'image_load', 'script', 'process_block', 'memory', 'credential_access',
          'create_remote_thread', 'host_integrity', 'wmi_activity', 'device_event',
          'tamper'
        ])) NOT VALID;
    RETURN;
  END IF;

  arr_body := substring(cur_def from 'ARRAY\[(.*)\]');
  IF arr_body IS NULL THEN
    RAISE EXCEPTION 'events_event_type_check has an unexpected shape, refusing to rewrite: %', cur_def;
  END IF;

  ALTER TABLE events DROP CONSTRAINT events_event_type_check;
  EXECUTE format(
    'ALTER TABLE events ADD CONSTRAINT events_event_type_check CHECK (event_type = ANY (ARRAY[%s, %L::text])) NOT VALID',
    arr_body, 'tamper');
END
$migration$;

-- ─────────────────────────────────────────────────────────────────────────────
-- Detection rules (DB side, evaluated by server-detect's RuleEngine).
--
-- The names carry a "(DB)" suffix because the same detections also ship as Go
-- builtins for server-api's AlertPipeline. The DB loader skips a rule whose title
-- collides with a builtin (PR #647, design note 1), so identical names would mean
-- these rows silently never load — the failure P4-10 hit with migration 329.
--
-- Both sides are populated on purpose. server-api is the path that has caught up
-- with the event stream; server-detect is the one that lags. For a signal that
-- means "someone is switching the sensor off", landing only on the lagging path
-- would be the wrong half to own.
--
-- mitre_tags is set on every row. The dedup layer filters on
-- mitre_technique IS NOT NULL, so a rule without attribution produces alerts that
-- are never deduplicated against the builtin's identical finding, and the analyst
-- sees each tamper event twice.
--
-- Severities are graded by how much the finding actually proves:
--   9  — an attempt or a change that nothing benign produces (signal kill, binary
--         swap, an explicit kill/handle-open against the agent PID).
--   8  — config rewritten under a running agent, or the supervisor vanishing.
--   6  — an unsignalled exit. Real, but a crash looks identical, and on Windows
--         it is genuinely indistinguishable from TerminateProcess. Scoring this a
--         9 would train analysts to dismiss the whole family.
--
-- ⚠ These severities are reasoned, not measured: the FP soak workflow cannot run
-- while the Actions quota is exhausted. Re-check them against a soak before
-- treating the numbers as calibrated.
-- ─────────────────────────────────────────────────────────────────────────────

-- ── T1562.001 : シグナルによるエージェント強制終了 ──────────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'EDR Agent Killed by Signal (DB)', 'sigma', ARRAY['linux','windows','macos'], 9,
$$
title: EDR Agent Killed by Signal (DB)
description: The EDR agent process was terminated by a signal that the watchdog did not send. Nothing inside the agent signals itself, and an operator-driven stop goes through the service manager, which cancels the watchdog first and is therefore not reported. A signalled death is external interference with the sensor (T1562.001).
status: stable
level: critical
tags:
  - attack.t1562.001
  - attack.defense_evasion
logsource:
  category: tamper
detection:
  selection:
    tamper_type: agent_killed
  condition: selection
falsepositives:
  - An out-of-band `kill` issued by an administrator debugging the agent
$$,
'community', ARRAY['T1562.001'],
'ウォッチドッグが観測した、シグナルによるエージェントの強制終了。センサー無効化の直接的な兆候。', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'EDR Agent Killed by Signal (DB)');

-- ── T1562.001 : シグナルによらないエージェントの予期しない終了 ──────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'EDR Agent Unexpected Exit (DB)', 'sigma', ARRAY['linux','windows','macos'], 6,
$$
title: EDR Agent Unexpected Exit (DB)
description: The EDR agent exited without a signal and without the watchdog asking it to. This is either a crash or, on Windows, a TerminateProcess that the exit code cannot be distinguished from. Either way the endpoint was unmonitored until the watchdog restarted it, which is why it is reported rather than only logged.
status: stable
level: medium
tags:
  - attack.t1562.001
  - attack.defense_evasion
logsource:
  category: tamper
detection:
  selection:
    tamper_type: agent_exited
  condition: selection
falsepositives:
  - A genuine agent crash. Investigate the agent log before treating it as an attack.
$$,
'community', ARRAY['T1562.001'],
'シグナルによらないエージェントの予期しない終了。クラッシュと強制終了の区別がつかないため中程度。', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'EDR Agent Unexpected Exit (DB)');

-- ── T1554 / T1562.001 : エージェントバイナリの改ざん ────────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'EDR Agent Binary Modified (DB)', 'sigma', ARRAY['linux','windows','macos'], 9,
$$
title: EDR Agent Binary Modified (DB)
description: The on-disk EDR agent binary no longer matches the digest recorded for it. Reported either by the start-up integrity check (a swap performed while the agent was down) or by the running agent re-hashing itself against an in-memory baseline (a swap performed underneath it). A legitimate update goes through the updater, which re-records the digest, so it does not produce this (T1554).
status: stable
level: critical
tags:
  - attack.t1554
  - attack.t1562.001
  - attack.defense_evasion
  - attack.persistence
logsource:
  category: tamper
detection:
  selection:
    tamper_type: binary_modified
  condition: selection
falsepositives:
  - A binary replaced by hand, outside the updater
$$,
'community', ARRAY['T1554','T1562.001'],
'エージェントバイナリのハッシュ不一致。正規アップデータ経由の更新では発生しない。', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'EDR Agent Binary Modified (DB)');

-- ── T1562.001 : エージェント設定の改ざん ────────────────────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'EDR Agent Config Modified (DB)', 'sigma', ARRAY['linux','windows','macos'], 8,
$$
title: EDR Agent Config Modified (DB)
description: The EDR agent config file changed while the agent was running. Rewriting the config defeats the sensor without touching a byte of its code — pointing it at a different server, or disabling collectors, leaves a healthy-looking agent that reports nothing useful (T1562.001).
status: stable
level: high
tags:
  - attack.t1562.001
  - attack.defense_evasion
logsource:
  category: tamper
detection:
  selection:
    tamper_type: config_modified
  condition: selection
falsepositives:
  - Configuration management (Ansible/Puppet/Chef) rewriting the file in place
$$,
'community', ARRAY['T1562.001'],
'稼働中にエージェント設定ファイルが変更された。コードを触らずセンサーを無力化する手口。', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'EDR Agent Config Modified (DB)');

-- ── T1562.001 : ウォッチドッグ（監視プロセス）の消滅 ────────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'EDR Watchdog Missing (DB)', 'sigma', ARRAY['linux','windows','macos'], 8,
$$
title: EDR Watchdog Missing (DB)
description: The agent is running but the watchdog process supervising it is gone. Killing the supervisor first is what makes killing the agent stick, so this frequently precedes the agent's own death rather than following it. The agent is the only half of the pair still alive to report it (T1562.001).
status: stable
level: high
tags:
  - attack.t1562.001
  - attack.defense_evasion
logsource:
  category: tamper
detection:
  selection:
    tamper_type: watchdog_missing
  condition: selection
falsepositives:
  - The watchdog crashed on its own
$$,
'community', ARRAY['T1562.001'],
'エージェントは稼働中だが監視役のウォッチドッグが消滅。エージェント停止の前段として起きやすい。', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'EDR Watchdog Missing (DB)');

-- ── T1562.001 : エージェントPIDへのkill/ハンドルオープン試行 ────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'EDR Agent Termination Attempt (DB)', 'sigma', ARRAY['linux','windows'], 9,
$$
title: EDR Agent Termination Attempt (DB)
description: Something tried to terminate the EDR agent and the kernel layer saw it — a kill against the protected PID (Linux eBPF LSM task_kill) or a handle carrying terminate/inject rights opened against it (Windows ObRegisterCallbacks). Unlike the watchdog's after-the-fact report, this names the process that tried, and fires whether or not the attempt succeeded.
status: stable
level: critical
tags:
  - attack.t1562.001
  - attack.defense_evasion
logsource:
  category: tamper
detection:
  selection:
    tamper_type:
      - kill_attempt
      - handle_open_attempt
  condition: selection
falsepositives:
  - Process management tooling enumerating handles across all processes
$$,
'community', ARRAY['T1562.001'],
'カーネル層が捉えたエージェントPIDへの終了試行。試行元プロセスまで特定できる。防御タグ有効時のみ発生。', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'EDR Agent Termination Attempt (DB)');
