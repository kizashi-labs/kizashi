-- アンインストール保護（テナント単位のアンインストールパスワード）
--
-- エンドポイントからエージェントを外すのに、端末利用者が持っていない秘密を要求する。
-- 検知だけの自己防護は「消されたこと」を後から教えるが、中堅以上の商用EDRはそもそも
-- アンインストールを拒否する。攻撃者がローカル管理者を取った直後にやることはセンサの
-- 除去なので、ここが通ると以降の可視性がまるごと消える。
--
-- 番号について: 378 は作業中の改ざんテレメトリ側で使用予定のため空けてある。
-- migrate.go はファイル名全体でソートするだけで連番性は要求せず、
-- migration_numbering_test.go が禁じているのは「重複」であって「欠番」ではない。

-- ─────────────────────────────────────────────────────────────
-- 1. ガード material（テナント単位）
--
-- 平文パスワードはここにも、エージェント側にも保存しない。保持するのは PBKDF2 の
-- salt と digest だけで、平文が存在するのは管理者が設定した瞬間のコンソール上のみ。
-- DB が丸ごと流出しても、フリート全体のアンインストールパスワードは得られない。
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS uninstall_guards (
    tenant_id  UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    version    INT  NOT NULL DEFAULT 1,
    -- 自己記述的にしておく。将来 KDF を変えたときに、古い行を誤って新しい方式で
    -- 検証してしまう事故を防ぐ。
    algorithm  TEXT NOT NULL DEFAULT 'pbkdf2-hmac-sha256',
    iterations INT  NOT NULL,
    salt       TEXT NOT NULL,   -- base64
    digest     TEXT NOT NULL,   -- base64
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- 誰が最後にローテートしたか。監査で最初に聞かれる。
    updated_by TEXT,
    CONSTRAINT uninstall_guards_iterations_sane CHECK (iterations >= 10000)
);

COMMENT ON TABLE  uninstall_guards IS 'テナント単位のアンインストールパスワード（PBKDF2 digest のみ。平文は保持しない）';
COMMENT ON COLUMN uninstall_guards.iterations IS 'PBKDF2 反復回数。エージェント側はこの値を使って検証するので、変更は即座にフリート全体に効く';

-- ─────────────────────────────────────────────────────────────
-- 2. アンインストール試行の記録
--
-- 拒否された試行のほうが重要。「センサを消そうとして、SOC の秘密を持っていなかった」
-- という事実そのものが調査対象になる。
--
-- agent_id に FK を張らない: 記録したい対象は「これから消えるエージェント」で、
-- 削除済み・未登録のエージェントからの通報も落とさず残す必要がある。
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS uninstall_attempts (
    id          BIGSERIAL PRIMARY KEY,
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    agent_id    UUID,
    hostname    TEXT,
    -- true  = 正しいパスワードでアンインストールが承認された（正規の廃止手続き）
    -- false = パスワードが違って拒否された（調査対象）
    authorised  BOOLEAN NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE uninstall_attempts IS 'アンインストール試行の記録。authorised=false は「センサ除去の試み」として調査対象';

-- 拒否された試行の新しい順が既定の見方。部分インデックスにしておくと、正規の
-- 廃止手続き（大半はこちら）で索引が太らない。
CREATE INDEX IF NOT EXISTS idx_uninstall_attempts_denied
    ON uninstall_attempts (tenant_id, occurred_at DESC)
    WHERE authorised = FALSE;

CREATE INDEX IF NOT EXISTS idx_uninstall_attempts_agent
    ON uninstall_attempts (agent_id, occurred_at DESC);

-- ─────────────────────────────────────────────────────────────
-- 3. RLS
--
-- 両表ともテナント秘密そのもの。既存表と同じポリシー形と、FORCE（テーブル所有者にも
-- 適用）を最初から付ける。後から足す形にすると、所有者接続だけ素通りする期間が
-- できる——このリポジトリで実際に起きたクロステナント BOLA と同じ形。
-- ─────────────────────────────────────────────────────────────
ALTER TABLE uninstall_guards   ENABLE ROW LEVEL SECURITY;
ALTER TABLE uninstall_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE uninstall_guards   FORCE ROW LEVEL SECURITY;
ALTER TABLE uninstall_attempts FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS uninstall_guards_tenant_isolation ON uninstall_guards;
CREATE POLICY uninstall_guards_tenant_isolation ON uninstall_guards
    USING (tenant_id::text = current_setting('app.tenant_id', TRUE)
           OR current_setting('app.tenant_id', TRUE) IS NULL
           OR current_setting('app.tenant_id', TRUE) = '');

DROP POLICY IF EXISTS uninstall_attempts_tenant_isolation ON uninstall_attempts;
CREATE POLICY uninstall_attempts_tenant_isolation ON uninstall_attempts
    USING (tenant_id::text = current_setting('app.tenant_id', TRUE)
           OR current_setting('app.tenant_id', TRUE) IS NULL
           OR current_setting('app.tenant_id', TRUE) = '');

-- アプリユーザへの権限。GRANT 漏れは RLS 切り替え時の定番の落とし穴で、
-- 「ポリシーは正しいのに permission denied」として現れる。
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'edr_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON uninstall_guards   TO edr_app;
        GRANT SELECT, INSERT                 ON uninstall_attempts TO edr_app;
        GRANT USAGE, SELECT ON SEQUENCE uninstall_attempts_id_seq  TO edr_app;
    END IF;
END $$;
