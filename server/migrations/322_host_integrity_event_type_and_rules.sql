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

-- Migration 322: allow 'host_integrity' in events.event_type, and add the Sigma
-- rules + a CommandLine gap-fill that ride on it.
--
-- New syscall-level Linux sensor (agent/ebpf/hostintegrity_monitor.bpf.c):
-- init_module/finit_module (T1547.006 kernel module load), unshare/setns
-- (T1611 namespace manipulation / container-host escape), capset (T1548.001
-- capability change). Existing coverage for these three techniques
-- (sigma_builtins.go "Kernel Module Loading (Linux)" / "Container Escape to
-- Host", migration 309's setuid-via-chmod rule) all key on CommandLine text
-- (insmod/modprobe/nsenter/chmod +s) — a custom or renamed binary calling the
-- syscall directly bypasses every one of them. The new events close that gap
-- at the syscall layer, independent of what the calling binary is named.
--
-- Same class of wiring bug as #269/#271/#294/314: without extending the CHECK
-- constraint, every host_integrity event INSERT is rejected (SQLSTATE 23514)
-- and silently dropped before any rule ever sees it.
--
-- The constraint is extended ADDITIVELY rather than by restating a hardcoded
-- list. Every prior migration in this family (294/314/…) rewrote the full
-- ARRAY literal, which makes the end state depend on migration ORDER: a
-- database that already allows event types added by migrations this file does
-- not know about (deployments have run migrations from branches not yet in
-- main — production at 2026-07-20 allowed named_pipe/wmi_activity/ps_classic/
-- device_event/resource_usage from such a branch) would SILENTLY LOSE them
-- when this file's hardcoded list replaced the constraint, rejecting those
-- events from then on. Reading the current definition and appending keeps the
-- result correct no matter which migrations ran before, and makes re-running
-- a no-op.
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
  IF cur_def IS NOT NULL AND position('''host_integrity''' in cur_def) > 0 THEN
    RETURN;
  END IF;

  -- NOT VALID on both paths below (added 2026-08-03). A VALIDATED constraint makes
  -- PostgreSQL check every existing row, so ONE legacy row carrying a type this
  -- migration does not list aborts it — and because the API runs migrations at
  -- startup and exits on failure, that is a restart loop plus every later migration
  -- silently unapplied. Migration 353 did exactly this in production. Rows like that
  -- exist wherever a deployment was upgraded across branches. Widening what is
  -- accepted going forward must not depend on assertions about the past; new INSERTs
  -- are still checked under NOT VALID, so nothing is lost defensively.
  --
  -- No constraint at all: create one from the known base set.
  IF cur_def IS NULL THEN
    ALTER TABLE events
      ADD CONSTRAINT events_event_type_check
        CHECK (event_type = ANY (ARRAY[
          'process', 'file', 'network', 'dns', 'registry', 'auth', 'process_stats',
          'image_load', 'script', 'process_block', 'memory', 'credential_access',
          'create_remote_thread', 'host_integrity'
        ])) NOT VALID;
    RETURN;
  END IF;

  -- Preserve every value the current constraint allows, then append ours.
  arr_body := substring(cur_def from 'ARRAY\[(.*)\]');
  IF arr_body IS NULL THEN
    RAISE EXCEPTION 'events_event_type_check has an unexpected shape, refusing to rewrite: %', cur_def;
  END IF;

  ALTER TABLE events DROP CONSTRAINT events_event_type_check;
  EXECUTE format(
    'ALTER TABLE events ADD CONSTRAINT events_event_type_check CHECK (event_type = ANY (ARRAY[%s, %L::text])) NOT VALID',
    arr_body, 'host_integrity');
END
$migration$;

-- ── T1547.006 : カーネルモジュールロード(syscallレベル) ──────────────
