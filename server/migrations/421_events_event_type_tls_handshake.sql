-- 367: events.event_type に 'tls_handshake' を追加する。
--
-- main の JA3/TLS 収集が promoteEventType に tls_handshake を追加したが、CHECK 制約
-- 側には入っていなかった。制約に無い種別の INSERT は SQLSTATE 23514 で棄却されるため、
-- TLS ハンドシェイクのイベントは1件も保存されず、JA3 系のルールは永久に発火しない。
--
-- この欠落は、2026-08-03 に追加した TestEventTypesAreAllowedByConstraint が
-- main をマージした直後に検出した（取り込み層が返しうる値と制約の突き合わせを
-- ソースから行うテスト）。#294 / #314 / ps_module ほか4種と同じ配線バグの、
-- 数えて7度目である。ガードが無ければ、また実機で測るまで露見しなかった。
--
-- 方式は 353 / 364 と同じ ADDITIVE + NOT VALID。理由はそちらのコメントを参照。
DO $migration$
DECLARE
  cur_def  text;
  existing text[] := ARRAY[]::text[];
  final    text[];
  tok      text;
  -- 取り込み層 (server/internal/ingestion/handler.go promoteEventType) が生成しうる種別
  -- ＋ 本番 DB に実在が確認された種別の和集合。promoteEventType が新しい種別を返すように
  -- なったら、ここにも足すこと。足し忘れるとそのイベントは INSERT 時に全件棄却される。
  want text[] := ARRAY[
    'process', 'file', 'network', 'dns', 'registry', 'auth', 'process_stats',
    'image_load', 'script', 'process_block', 'memory', 'credential_access',
    'create_remote_thread', 'host_integrity', 'parent_pid_spoof',
    -- promoteEventType が返すのに、どの制約にも入っていなかったもの（Windows 側で全件棄却されていた）
    'ps_module', 'pipe_created', 'eventlog_cleared', 'service_installed', 'device_event',
    -- 別系統ブランチ由来で本番 DB に実在した種別
    'named_pipe', 'wmi_activity', 'ps_classic', 'resource_usage',
    -- main の JA3/TLS 収集が追加した種別
    'tls_handshake'
  ];
BEGIN
  SELECT pg_get_constraintdef(c.oid) INTO cur_def
    FROM pg_constraint c
   WHERE c.conname = 'events_event_type_check'
     AND c.conrelid = 'events'::regclass
   LIMIT 1;

  IF cur_def IS NOT NULL THEN
    IF position('ARRAY[' in cur_def) = 0 THEN
      RAISE EXCEPTION 'events_event_type_check has an unexpected shape, refusing to rewrite: %', cur_def;
    END IF;
    -- 現在許可されている値を1つも落とさずに取り出す。過去に配列リテラル連結
    -- (ARRAY[...] || '{a,b}'::text[]) で書かれた版も読めるよう、両方の形を展開する。
    FOR tok IN SELECT (regexp_matches(cur_def, '''([^'']*)''', 'g'))[1] LOOP
      IF tok LIKE '{%}' THEN
        existing := existing || string_to_array(btrim(tok, '{}'), ',');
      ELSE
        existing := array_append(existing, tok);
      END IF;
    END LOOP;

    -- 望む種別がすべて既に許可されている: 再実行は no-op。
    IF want <@ existing THEN
      RETURN;
    END IF;
  END IF;

  SELECT array_agg(DISTINCT x ORDER BY x) INTO final FROM unnest(existing || want) AS x;

  IF cur_def IS NOT NULL THEN
    ALTER TABLE events DROP CONSTRAINT events_event_type_check;
  END IF;
  -- 常に「要素ごとに引用符で囲んだ単一の ARRAY[]」形で書き戻す。表現を揃えておかないと、
  -- 次回この移行が現定義を読むときに取りこぼす（連結形で書いた初版がそれで壊れた）。
  EXECUTE format(
    'ALTER TABLE events ADD CONSTRAINT events_event_type_check
       CHECK (event_type = ANY (ARRAY[%s])) NOT VALID',
    (SELECT string_agg(quote_literal(x) || '::text', ', ' ORDER BY x) FROM unnest(final) AS x));
END
$migration$;
