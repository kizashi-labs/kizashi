-- 380: allow 'tls_handshake', 'ps_module', 'pipe_created', 'eventlog_cleared',
--      'service_installed' in events.event_type.
--
-- promoteEventType (internal/ingestion/handler.go) は、これら 5 種の id 接頭辞
-- ("tls_handshake:" / "ps_module:" / "pipe_created:" / "eventlog_cleared:" /
-- "service_installed:") をそれぞれの型に解決する。エージェント側の 5 コレクタは
-- cmd/agent/main.go で本番ビルドに結線済みで、Windows 端末では実際に流れている。
-- にもかかわらず、この 5 値を events_event_type_check に載せた migration は
-- 一本も存在しない。制約は 002 の 6 値で作られ、以後 225/269/271/294/314/322/370/373
-- が「自分の 1 値だけ」を追記してきたが、この 5 つはどの回にも含まれなかった。
--
-- 結果として、導入(2026-07-09〜07-20)以来ずっと INSERT が 23514 で拒否されている。
-- 269 が process_block / image_load / script で、373 が device_event で踏んだのと
-- 同一クラスの欠陥で、これで 3 度目になる:
--
--   * publishEventBatch は「先に永続化し、その後 NATS へ publish」する。DB が拒否
--     しても publish は走るので、検知は鳴るのに events テーブルには証跡が残らない。
--     イベント API・タイムライン・脅威ハンティング・レトロハントから、
--     TLS フィンガープリント / PowerShell モジュールログ / 名前付きパイプ /
--     イベントログ消去 / サービス作成だけが見えない。
--     とくに eventlog_cleared (T1070.001) と service_installed (T1543.003) は
--     痕跡消去・永続化という、事後調査でこそ引かれる証跡である。
--   * insertEvents は 500 件ごとの複数行 INSERT が失敗すると 1 件ずつの INSERT に
--     フォールバックする。拒否される 1 件を含むバッチは 1 往復が 501 往復に化ける。
--     Windows 端末では ps_module / pipe_created が高頻度で出るため、この劣化は
--     恒常的に効いている。
--
-- 370/373 と同じく、現在の定義を読んで**追記する**形にする(既存の許可値、とくに
-- out-of-tree branch 由来の値を取りこぼさないため)。値ごとに存在確認するので
-- 再実行しても、5 値の一部が既に許可済みの環境でも安全。
--
-- 再発防止は SQL では書けないため Go 側に置いた:
-- internal/ingestion/event_type_constraint_test.go が、promoteEventType が返しうる
-- 型の集合を migrations から復元した制約集合と突き合わせ、欠けていれば落ちる。

DO $migration$
DECLARE
  cur_def  text;
  arr_body text;
  missing  text;
BEGIN
  FOREACH missing IN ARRAY ARRAY[
    'tls_handshake', 'ps_module', 'pipe_created', 'eventlog_cleared', 'service_installed'
  ] LOOP
    SELECT pg_get_constraintdef(c.oid) INTO cur_def
      FROM pg_constraint c
     WHERE c.conname = 'events_event_type_check'
       AND c.conrelid = 'events'::regclass
     LIMIT 1;

    -- 制約が無い環境: 既知のベース集合 + 今回の 5 値で作り直す。
    IF cur_def IS NULL THEN
      ALTER TABLE events
        ADD CONSTRAINT events_event_type_check
          CHECK (event_type = ANY (ARRAY[
            'process', 'file', 'network', 'dns', 'registry', 'auth', 'process_stats',
            'image_load', 'script', 'process_block', 'memory', 'credential_access',
            'create_remote_thread', 'host_integrity', 'wmi_activity', 'device_event',
            'tls_handshake', 'ps_module', 'pipe_created', 'eventlog_cleared',
            'service_installed'
          ]));
      RETURN;
    END IF;

    -- 既に許可されている(再実行、または branch 由来): この値はスキップ。
    CONTINUE WHEN position('''' || missing || '''' in cur_def) > 0;

    arr_body := substring(cur_def from 'ARRAY\[(.*)\]');
    IF arr_body IS NULL THEN
      RAISE EXCEPTION 'events_event_type_check has an unexpected shape, refusing to rewrite: %', cur_def;
    END IF;

    ALTER TABLE events DROP CONSTRAINT events_event_type_check;
    EXECUTE format(
      'ALTER TABLE events ADD CONSTRAINT events_event_type_check CHECK (event_type = ANY (ARRAY[%s, %L::text]))',
      arr_body, missing);
  END LOOP;
END
$migration$;
