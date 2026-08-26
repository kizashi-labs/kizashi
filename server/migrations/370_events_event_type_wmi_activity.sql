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

-- 370: allow 'wmi_activity' in events.event_type, and add the WMI event-subscription
-- persistence rule that consumes it.
--
-- The WMI-Activity ETW sensor (agent/internal/platform/windows/wmi_etw.go) promotes
-- to event_type 'wmi_activity'. Without this the ingestion INSERT is rejected by
-- events_event_type_check and every WMI observation is lost at the door — the same
-- shape as the six column/constraint mismatches fixed on 2026-08-03, where the
-- write failed silently and the feature looked merely quiet.
--
-- Rewrite preserves whatever the constraint currently allows rather than restating a
-- fixed list, because several migrations have extended it independently and a
-- restatement would silently drop the ones added since this file was written.
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

  -- Already permitted (re-run, or a later migration added it): nothing to do.
  IF cur_def IS NOT NULL AND position('''wmi_activity''' in cur_def) > 0 THEN
    RETURN;
  END IF;

  -- No constraint at all: create one from the known base set.
  IF cur_def IS NULL THEN
    ALTER TABLE events
      ADD CONSTRAINT events_event_type_check
        CHECK (event_type = ANY (ARRAY[
          'process', 'file', 'network', 'dns', 'registry', 'auth', 'process_stats',
          'image_load', 'script', 'process_block', 'memory', 'credential_access',
          'create_remote_thread', 'host_integrity', 'wmi_activity'
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
    arr_body, 'wmi_activity');
END
$migration$;

-- ── T1546.003 : WMI イベントサブスクリプションによる永続化 ──────────────
--
-- 5861 (subscription registered) carries the WQL filter and the consumer in one
-- record. A CommandLineEventConsumer or ActiveScriptEventConsumer bound to a
-- filter is the classic fileless persistence: nothing on disk, survives reboot,
-- and no process-creation event names WMI as the parent.
--
-- The rule keys on the CONSUMER TYPE, not on the mere presence of a subscription.
-- Management products (SCCM, monitoring agents) register subscriptions routinely;
-- what distinguishes the technique is a consumer that executes something.
--
-- This is the server-detect half of a pair: the same rule ships as a built-in in
-- sigma_builtins.go so server-api's AlertPipeline evaluates it too. Both halves are
-- required — the two services load different rule sources, so a DB-only rule leaves
-- the primary alert path dark (docs/検知ルールの二重管理とデプロイ.md). Keep the
-- detection block below in sync with the built-in.
--
-- This does NOT duplicate migration 329's "WMI Event Subscription Persistence (DB)".
-- That rule is process_creation: it matches the wmic command line that creates a
-- subscription. This one is wmi_event: it matches the registration as reported by
-- the WMI subsystem itself, so it also covers the paths that never spawn wmic —
-- Set-WmiInstance from PowerShell, ManagementClass from .NET, or any in-process
-- WMI client. Same technique, different observation surface; keeping both is the
-- same reasoning applied to the LOLBin rules in #592, and giving them distinct
-- names is what keeps the DB-rule extractor from silently overwriting one with
-- the other (it identifies rules by name).
