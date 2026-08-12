-- 328: alerts / incidents に tenant_id DEFAULT を付与(edr_app 切替の前提整備)。
--
-- 背景(2026-07 監査): alerts/incidents は migration 027 で RLS 済みだが、
-- tenant_id の DEFAULT が無い(DEFAULT を持つのは agents=244 / users=326 のみ)。
-- API プロセス内の多数のバックグラウンドワーカ(IOCMatcher / RealtimeCorrelator /
-- VulnerabilityScanner / HeartbeatMonitor / 各種 detector 等 約15本)は
-- `INSERT INTO alerts` で tenant_id を設定しない。現状(スーパーユーザ接続で RLS
-- 素通り)では問題化しないが、edr_app(非スーパーユーザ)へ切替えると:
--   * これらのワーカは app.tenant_id 未設定 → エスケープ節で INSERT 自体は許可
--     されるが、行の tenant_id は NULL のまま。
--   * NULL テナントのアラート/インシデントは、app.tenant_id を設定した認証済み API
--     リクエストからは RLS で不可視になる(単一テナントでも既定テナント ≠ NULL)。
-- = edr_app 有効化後にアラート/インシデントが UI から消える潜在バグ。
--
-- 是正: users(326)と同型の動的 DEFAULT を付与。
--   * 認証済みリクエスト(app.tenant_id=T)からの手動作成 → T に所属
--   * バックグラウンドワーカ(app.tenant_id 未設定)→ 既定テナントにフォールバック
--     (単一テナント運用では正しく既定テナント。マルチテナントでも NULL より可視で
--      安全。理想は agent→tenant 解決だが、それは別途アプリ側改修=手順書 section 3)。
-- 既存 NULL 行はバックフィル。
--
-- 冪等: DEFAULT/backfill は再実行安全。

-- alerts
ALTER TABLE alerts
    ALTER COLUMN tenant_id SET DEFAULT COALESCE(
        NULLIF(current_setting('app.tenant_id', true), '')::uuid,
        '00000000-0000-0000-0000-000000000001'
    );
UPDATE alerts
SET tenant_id = '00000000-0000-0000-0000-000000000001'
WHERE tenant_id IS NULL;

-- incidents
ALTER TABLE incidents
    ALTER COLUMN tenant_id SET DEFAULT COALESCE(
        NULLIF(current_setting('app.tenant_id', true), '')::uuid,
        '00000000-0000-0000-0000-000000000001'
    );
UPDATE incidents
SET tenant_id = '00000000-0000-0000-0000-000000000001'
WHERE tenant_id IS NULL;
