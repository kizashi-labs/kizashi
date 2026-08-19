-- Migration 353 (was 323 on the analysis branch): allow 'parent_pid_spoof' in
-- events.event_type.
--
-- The Windows ETW process-start sensor (Kernel-Process provider, gated opt-in)
-- emits event_type='parent_pid_spoof' when a process creation's REAL creator
-- (ETW event-header PID) disagrees with the recorded/claimed parent (payload
-- ParentProcessID) under the conservative T1134.004 heuristic
-- (agent/internal/collector/ppid_spoof.go IsSuspiciousParentSpoof) — Parent PID
-- Spoofing (Access Token Manipulation).
--
-- The CHECK constraint omits 'parent_pid_spoof', so every such INSERT would be
-- rejected with SQLSTATE 23514 and the events silently dropped — the same
-- wiring-bug class as #294 / #314. Extend it. Idempotent.
--
-- ── 2026-08-03: この移行が本番 DB で API を再起動ループに落とした ──────────
-- 当初この移行は制約を「ハードコードした配列で全置換」していた。migration 322 が
-- まさにその方式の危険性を明記していたにもかかわらず、である（322 の冒頭コメント:
-- 「配列を書き直す方式は最終状態が移行の順序に依存する。この移行が知らないイベント種別を
--   既に許可している DB では、それらが黙って弾かれるようになる」）。実際に起きたのは:
--
--   1. 本番 DB には別系統のブランチが投入した wmi_activity / named_pipe の行が実在した
--      （制約が NOT VALID で追加されていたため、過去行は検証を免れて残っていた）
--   2. この移行が検証付きの制約を張ろうとし、その過去行に引っかかって SQLSTATE 23514
--   3. マイグレーション失敗 → API 起動失敗 → 再起動ループ。以降の移行(354〜)も一切
--      適用されず、20本超のルール追加が丸ごと欠落した状態で数日間稼働していた
--
-- 対処は3点。いずれも「制約は防御であって、起動を止める仕掛けであってはならない」に沿う。
--
--   (a) 322 と同じ ADDITIVE 方式にする。現在の定義を読んで追記するので、この移行が
--       知らない種別を持つ DB でも取りこぼさない。
--   (b) 取り込み層 (server/internal/ingestion/handler.go promoteEventType) が実際に
--       生成しうる種別を全部入れる。ps_module / pipe_created / eventlog_cleared /
--       service_installed / device_event は promoteEventType が返すのに、どの制約にも
--       入っていなかった＝Windows エンドポイントではこれらのイベントが INSERT 時に
--       全件棄却されていた。まさに #294/#314 と同じ配線バグがもう5種類埋まっていた。
--   (c) NOT VALID で張る。過去行の検証は行わない。検証付きの制約は、レガシー行が1行でも
--       あれば移行を失敗させ、API を起動不能にする。新規 INSERT は NOT VALID でも
--       通常どおり検証されるので、防御力は落ちない。落ちるのは「過去データを遡って
--       保証する」性質だけで、それは起動可用性と引き換えにする価値がない。
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
