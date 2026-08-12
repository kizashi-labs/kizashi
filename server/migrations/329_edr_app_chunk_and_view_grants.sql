-- 329: edr_app への GRANT 漏れを塞ぐ(TimescaleDB chunk / マテビュー / 連続集計)。
--
-- 背景: migration 325 は `GRANT ... ON ALL TABLES IN SCHEMA public` で権限を
-- 付与しているが、この構文には 2 つの取りこぼしがある:
--
--   (1) **マテリアライズドビュー**: PostgreSQL の `ALL TABLES IN SCHEMA` は
--       テーブル・ビュー・外部テーブル・パーティション親のみを対象とし、
--       マテビューを **含まない**(PostgreSQL の仕様)。
--   (2) **TimescaleDB の chunk**: 実体は `_timescaledb_internal` スキーマに
--       あり `public` の走査対象外。hypertable への明示 GRANT は TimescaleDB が
--       chunk へ伝播させる(新規 chunk にも hypertable の ACL が引き継がれる)が、
--       `ALL TABLES IN SCHEMA` 経由での伝播は保証されない。
--
-- 影響: `edr_app` へ切り替えた環境で events / network_connections 等の
-- hypertable を読む画面だけが `permission denied` で空表示・500 になり得る。
-- 手順書のドライラン(`relkind='r' AND nspname='public'` の has_table_privilege
-- 集計)はこの 2 つを走査対象外にしているため、事前検知できなかった。
--
-- 対処: hypertable / 連続集計 / ビュー / マテビューへ明示 GRANT する。
--
-- 冪等: GRANT は繰り返し安全。edr_app 未作成の環境・TimescaleDB 拡張が無い
-- 環境では該当ブロックを丸ごとスキップするため、どちらでも壊れない。

DO $$
DECLARE
    r record;
BEGIN
    -- edr_app は migration 325 で作成される。未作成なら何もしない。
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'edr_app') THEN
        RETURN;
    END IF;

    -- (A) hypertable へ明示 GRANT。TimescaleDB が既存 chunk へ伝播させ、
    --     以後に作られる chunk も hypertable の ACL を引き継ぐ。
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb') THEN
        FOR r IN
            SELECT format('%I.%I', hypertable_schema, hypertable_name) AS rel
            FROM timescaledb_information.hypertables
        LOOP
            EXECUTE format(
                'GRANT SELECT, INSERT, UPDATE, DELETE ON %s TO edr_app', r.rel);
        END LOOP;

        -- 連続集計(events_hourly / events_daily)は読み取りのみ。
        FOR r IN
            SELECT format('%I.%I', view_schema, view_name) AS rel
            FROM timescaledb_information.continuous_aggregates
        LOOP
            EXECUTE format('GRANT SELECT ON %s TO edr_app', r.rel);
        END LOOP;
    END IF;

    -- (B) public のビュー / マテビュー / パーティション親。
    --     マテビュー('m')が ALL TABLES の取りこぼし本体。
    FOR r IN
        SELECT format('%I.%I', n.nspname, c.relname) AS rel, c.relkind
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public'
          AND c.relkind IN ('v', 'm', 'p')
    LOOP
        IF r.relkind = 'p' THEN
            EXECUTE format(
                'GRANT SELECT, INSERT, UPDATE, DELETE ON %s TO edr_app', r.rel);
        ELSE
            EXECUTE format('GRANT SELECT ON %s TO edr_app', r.rel);
        END IF;
    END LOOP;
EXCEPTION
    -- この migration は権限の「積み増し」のみで、スキーマは一切変更しない。
    -- 想定外の環境(TimescaleDB のバージョン差でビュー定義が違う等)で失敗した
    -- 場合に API の起動ごと止めるのは割に合わないため、警告に落として続行する。
    -- 付与漏れは手順書のドライラン query / scripts/diagnose-data-display.sh の
    -- セクション 11-12 で検出できる。
    WHEN OTHERS THEN
        RAISE WARNING '329: edr_app への chunk/view GRANT に失敗しました (%). 手順書のドライラン query で missing_* を確認してください。', SQLERRM;
END
$$;
