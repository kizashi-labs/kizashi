-- 326: users テーブルにマルチテナント RLS を追加(テナント分離ハードニング 手順書 section 3)。
--
-- 背景: users は tenant_id 列(migration 027)を持つが RLS 未設定で、`List` 等が
-- テナントフィルタ無しに全テナントのユーザを返す残余リスクがあった(agents/alerts/
-- incidents は 027+324 で RLS 済み)。本 migration は users を同じ RLS モデルに載せる。
--
-- ★NULL テナント問題の是正が前提(agents が migration 244 で踏んだ地雷の users 版):
--   Create / SeedAdminUser / 管理API / LDAP JIT の INSERT は tenant_id を設定せず
--   NULL を残す。RLS 下では NULL 行は不可視になり、かつ app.tenant_id を設定した
--   認証済みリクエストからの INSERT が(USING を WITH CHECK に流用する PostgreSQL の
--   仕様で)拒否される。これを Go コードを変えずに解決するため、列 DEFAULT を
--   「接続の app.tenant_id があればそれ、無ければ既定テナント」に評価する式にする:
--     * 認証済み API リクエスト(app.tenant_id=T)→ 新規ユーザは T に所属 → WITH CHECK 通過
--     * バックグラウンド/起動時(SeedAdminUser 等, app.tenant_id 未設定)→ 既定テナント
--       かつエスケープ節で INSERT 許可
--   CreateFromInvitation / billing は既に tenant_id を明示するため DEFAULT は不使用。
--
-- 冪等: DEFAULT/backfill/FORCE は再実行安全。ポリシーは存在チェックしてから作成。

-- 1. 列 DEFAULT を「app.tenant_id 優先・無ければ既定テナント」に。
--    current_setting(..., true) は未設定で NULL、解放後は '' になるため NULLIF で吸収。
ALTER TABLE users
    ALTER COLUMN tenant_id SET DEFAULT COALESCE(
        NULLIF(current_setting('app.tenant_id', true), '')::uuid,
        '00000000-0000-0000-0000-000000000001'
    );

-- 2. 既存の NULL テナント行(027 後に作成された admin/管理/LDAP ユーザ等)をバックフィル。
UPDATE users
SET tenant_id = '00000000-0000-0000-0000-000000000001'
WHERE tenant_id IS NULL;

-- 3. RLS を有効化 + FORCE(所有者も対象)。
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE users FORCE ROW LEVEL SECURITY;

-- 4. ポリシー: agents/alerts/incidents(migration 027)と同型のエスケープ節付き。
--    app.tenant_id 未設定(login 前・バックグラウンド)は全件アクセス、設定時は自テナント。
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public' AND tablename = 'users'
          AND policyname = 'users_tenant_isolation'
    ) THEN
        CREATE POLICY users_tenant_isolation ON users
            USING (tenant_id::text = current_setting('app.tenant_id', TRUE)
                   OR current_setting('app.tenant_id', TRUE) IS NULL
                   OR current_setting('app.tenant_id', TRUE) = '');
    END IF;
END
$$;
