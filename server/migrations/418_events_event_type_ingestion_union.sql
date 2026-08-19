-- Migration 364: events.event_type の CHECK 制約を「取り込み層が生成しうる種別の
-- 和集合」に揃える。353 と同じ内容を、353 を既に適用済みの DB のために再実行する。
--
-- なぜ2本必要か:
--   353 は当初ハードコード配列で制約を全置換していた。その版を適用済みの DB は
--   schema_migrations に 353 を記録しているため、353 を直しても再実行されない。
--   結果、それらの DB では promoteEventType が返す ps_module / pipe_created /
--   eventlog_cleared / service_installed / device_event が制約に無いまま残り、
--   Windows エンドポイントのこれらのイベントが INSERT 時に全件棄却され続ける
--   （#294 / #314 と同じ配線バグ）。この移行がその穴を塞ぐ。
--   353 未適用の DB では 353 側が先に同じ状態にするので、ここは何もしない no-op になる。
--
-- 方針は 322 / 353 と同じ:
--   ADDITIVE  — 現在許可されている値は1つも落とさない（この移行が知らない種別を持つ
--               DB でも取りこぼさない）
--   NOT VALID — 過去行は検証しない。検証付き制約はレガシー行1行で移行を失敗させ、
--               API を起動不能にする（実際に 2026-08-03 に再起動ループを起こした）。
--               新規 INSERT は NOT VALID でも検証されるので防御力は落ちない。
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
    'named_pipe', 'wmi_activity', 'ps_classic', 'resource_usage'
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
