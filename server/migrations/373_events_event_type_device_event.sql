-- 373: allow 'device_event' in events.event_type.
--
-- promoteEventType (internal/ingestion/handler.go) は "device_event:<uuid>:<json>"
-- 封筒に対して "device_event" を返す。にもかかわらず、この値を
-- events_event_type_check に載せた migration は一本も無い。つまり USB / リムーバブル
-- メディアの挿抜は、クリーンな環境では **INSERT が毎回 23514 で拒否される**。
--
-- 症状が静かなのがこの欠陥の性質:
--
--   * publishEventBatch は「先に永続化し、その後 NATS へ publish」する。DB が
--     拒否しても publish は走るので、検知は動くのに events テーブルには証跡が
--     残らない。イベント API・タイムライン・脅威ハンティング・各種レポートから
--     USB 挿抜だけが見えない状態になる。
--   * insertEvents は 500 件ごとの複数行 INSERT が失敗すると 1 件ずつの INSERT に
--     フォールバックする。拒否される 1 件を含むバッチは 1 往復が 501 往復に化ける。
--
-- 322 のコメントが「本番(2026-07-20)は branch 由来で device_event を許可していた」
-- と書いているとおり、環境によっては既に許可されている。そのため 370 と同じく
-- 現在の定義を読んで追記する形にし、既存の許可値を取りこぼさないようにする。

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
  IF cur_def IS NOT NULL AND position('''device_event''' in cur_def) > 0 THEN
    RETURN;
  END IF;

  -- No constraint at all: create one from the known base set.
  IF cur_def IS NULL THEN
    ALTER TABLE events
      ADD CONSTRAINT events_event_type_check
        CHECK (event_type = ANY (ARRAY[
          'process', 'file', 'network', 'dns', 'registry', 'auth', 'process_stats',
          'image_load', 'script', 'process_block', 'memory', 'credential_access',
          'create_remote_thread', 'host_integrity', 'wmi_activity', 'device_event'
        ]));
    RETURN;
  END IF;

  arr_body := substring(cur_def from 'ARRAY\[(.*)\]');
  IF arr_body IS NULL THEN
    RAISE EXCEPTION 'events_event_type_check has an unexpected shape, refusing to rewrite: %', cur_def;
  END IF;

  ALTER TABLE events DROP CONSTRAINT events_event_type_check;
  EXECUTE format(
    'ALTER TABLE events ADD CONSTRAINT events_event_type_check CHECK (event_type = ANY (ARRAY[%s, %L::text]))',
    arr_body, 'device_event');
END
$migration$;
