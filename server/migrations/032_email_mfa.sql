-- メールOTP MFA サポート
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_type TEXT NOT NULL DEFAULT 'totp' CHECK (mfa_type IN ('totp', 'email', 'none'));

CREATE TABLE IF NOT EXISTS email_otp_codes (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code       TEXT NOT NULL,           -- bcryptハッシュ化済み
    purpose    TEXT NOT NULL DEFAULT 'mfa',  -- 'mfa' | 'login'
    expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '10 minutes',
    used       BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_email_otp_user ON email_otp_codes(user_id) WHERE NOT used;
