-- 234_signup_registrations.sql
-- セルフサービスサインアップ用仮登録テーブル
--
-- フロー:
--   pending       : POST /api/v1/signup でメールと会社情報を登録。認証トークンを発行し認証メール送信。
--   email_verified: POST /api/v1/signup/verify-email でトークン照合後に遷移。
--   checkout_created: POST /api/v1/signup/create-checkout で Stripe Checkout Session を発行。
--   completed     : Stripe webhook (checkout.session.completed) 処理で tenant と admin user を作成し完了。
--
-- pending のまま 72 時間経過したレコードはバックグラウンドジョブで削除する想定。

CREATE TABLE IF NOT EXISTS signup_registrations (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email                   TEXT NOT NULL,
    password_hash           TEXT NOT NULL,              -- bcrypt ハッシュ
    company_name            TEXT NOT NULL,
    full_name               TEXT NOT NULL,
    desired_plan            TEXT NOT NULL,              -- starter | business | enterprise
    agent_count             INT  NOT NULL DEFAULT 1 CHECK (agent_count >= 1),

    -- 状態遷移
    status                  TEXT NOT NULL DEFAULT 'pending'
                              CHECK (status IN ('pending','email_verified','checkout_created','completed','expired')),

    -- メール認証
    verification_token      TEXT NOT NULL UNIQUE,
    verification_expires_at TIMESTAMPTZ NOT NULL,
    verified_at             TIMESTAMPTZ,

    -- Stripe
    stripe_session_id       TEXT,                       -- checkout.sessions.new の返却 ID
    stripe_customer_id      TEXT,                       -- webhook で紐付け
    checkout_created_at     TIMESTAMPTZ,

    -- 完了時リンク
    tenant_id               UUID REFERENCES tenants(id) ON DELETE SET NULL,
    admin_user_id           UUID REFERENCES users(id)   ON DELETE SET NULL,
    completed_at            TIMESTAMPTZ,

    -- 監査
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    source_ip               INET,
    user_agent              TEXT
);

CREATE INDEX IF NOT EXISTS idx_signup_registrations_email      ON signup_registrations(email);
CREATE INDEX IF NOT EXISTS idx_signup_registrations_status     ON signup_registrations(status);
CREATE INDEX IF NOT EXISTS idx_signup_registrations_session    ON signup_registrations(stripe_session_id);
CREATE INDEX IF NOT EXISTS idx_signup_registrations_token      ON signup_registrations(verification_token);

-- 同じメールアドレスで pending/email_verified が複数走らないようにするための部分ユニーク制約
CREATE UNIQUE INDEX IF NOT EXISTS uq_signup_registrations_email_active
    ON signup_registrations(email)
    WHERE status IN ('pending','email_verified','checkout_created');
