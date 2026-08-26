-- 327: edr_app ロールの権限を最小化(テナント分離ハードニング 手順書 section 3)。
--
-- migration 325 は簡潔さのため public スキーマの全テーブルに CRUD を付与した。
-- アプリ実行時ロール edr_app は migration 管理用テーブルを書き換える必要が無い。
-- アプリ侵害(SQLi 等)時に migration 履歴を改竄されないよう、書込権限を剥奪する
-- (可観測性のため SELECT は残す)。
--
-- 冪等: REVOKE は繰り返し安全。対象テーブルが未作成の環境でも壊れないよう
-- to_regclass で存在チェックしてから実行する。migration ランナーは
-- schema_migrations を loop 前に CREATE TABLE IF NOT EXISTS するため通常は存在する。

DO $$
BEGIN
    -- migration 追跡テーブル: アプリからは読み取りのみ許可。
    IF to_regclass('public.schema_migrations') IS NOT NULL THEN
        EXECUTE 'REVOKE INSERT, UPDATE, DELETE ON public.schema_migrations FROM edr_app';
    END IF;
END
$$;
