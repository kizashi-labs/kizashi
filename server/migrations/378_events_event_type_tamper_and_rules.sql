--
-- ─── 公開版向けの差し替え（scripts/public-snapshot/overlay） ──────────────
--
-- 本流の同名ファイルは、スキーマ変更のあとに検知ルールの INSERT が続く。
-- 公開版は検知コンテンツをパックで配るので、**スキーマ変更だけを残し、
-- INSERT を落とした版**がこれ。
--
-- ファイルごと除外できないのは、events_event_type_check の付け替えなど
-- スキーマ側が公開版でも必要なため。番号とファイル名は本流と同一にする
-- （schema_migrations は version としてファイル名を持つので、名前を変えると
-- 適用済みの環境で再実行される）。
--
-- 落としたルールは rulepacks/ に入っている。公開版に同梱されるのは
-- baseline.json のみ。
--

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
