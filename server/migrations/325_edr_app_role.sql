-- 325: 非スーパーユーザ・アプリロール edr_app を作成し CRUD 権限を付与
--      (マルチテナント RLS 分離ハードニング 手順2 のコード化)。
--
-- 背景(2026-07 セキュリティ監査): migration 324 で agents/alerts/incidents を
-- FORCE ROW LEVEL SECURITY 化したが、アプリが DB スーパーユーザ edr
-- (rolsuper=t, rolbypassrls=t) で接続する限り RLS は無条件素通りのまま
-- (docs/security/マルチテナント分離ハードニング.md 原因#1)。本 migration は
-- 非スーパーユーザ・非BYPASSRLS のアプリロール edr_app を用意し、RLS が実効
-- する接続主体をコード管理下で提供する。
--
-- ★重要 — この migration だけではテナント分離は「有効化」されない(安全な準備段階):
--   * edr_app は NOLOGIN・パスワード未設定で作成される(Secret を git に載せない
--     ため)。この状態では接続に使えず、既存挙動は一切変わらない。
--   * 実際の切替はオペレータが意図的に行う 2 ステップ:
--       (1) パスワード付与 + ログイン許可(値は Secret から。git に残さない):
--             ALTER ROLE edr_app WITH LOGIN PASSWORD '<Secret のパスワード>';
--       (2) アプリの APP_DATABASE_URL を edr_app の DSN に切替(全サービス)。
--             例: postgres://edr_app:<pass>@postgres:5432/edrplatform?sslmode=...
--     詳細・検証手順は docs/security/マルチテナント分離ハードニング.md 手順2/手順3。
--
-- migration は引き続き所有者ロール(DATABASE_URL / edr)で実行される前提。DDL に
-- 所有者権限が要るため、アプリ実行時接続(APP_DATABASE_URL / edr_app)とは別経路。
--
-- 冪等: ロール作成は pg_roles を確認。GRANT / ALTER DEFAULT PRIVILEGES は繰り返し
-- 実行しても安全。

-- (A) 非スーパーユーザ・非BYPASSRLS のアプリロールを作成(NOLOGIN + パスワード未設定)。
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'edr_app') THEN
        -- NOLOGIN・パスワード未設定で作成する。切替時にオペレータが
        -- ALTER ROLE edr_app WITH LOGIN PASSWORD '<Secret>' で有効化する。
        CREATE ROLE edr_app NOLOGIN NOSUPERUSER NOBYPASSRLS
            NOCREATEDB NOCREATEROLE NOREPLICATION;
    END IF;
END
$$;

-- (B) スキーマ利用権 + 既存の全テーブル/シーケンスへ CRUD 権限。
GRANT USAGE ON SCHEMA public TO edr_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO edr_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO edr_app;

-- (C) 以後 migration(所有者ロールが実行)で作られるオブジェクトにも自動付与。
-- ALTER DEFAULT PRIVILEGES の FOR ROLE は「将来オブジェクトを作成するロール」=
-- migration 実行ロール(current_user)を指す必要があるため、DO ブロックで動的に
-- 組み立てる(ロール名 'edr' を直書きせず、実行環境の所有者名に追従させる)。
DO $$
BEGIN
    EXECUTE format(
        'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public '
        || 'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO edr_app',
        current_user);
    EXECUTE format(
        'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public '
        || 'GRANT USAGE, SELECT ON SEQUENCES TO edr_app',
        current_user);
END
$$;
