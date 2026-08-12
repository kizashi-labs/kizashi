-- MFA (TOTP) サポート
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS mfa_secret      TEXT,
    ADD COLUMN IF NOT EXISTS mfa_enabled     BOOLEAN NOT NULL DEFAULT FALSE;

-- バックアップコード: 各ユーザーが最大10個の使い捨てコードを持つ
CREATE TABLE IF NOT EXISTS mfa_backup_codes (
    id         TEXT PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash  TEXT NOT NULL,   -- bcrypt hash of the 8-digit code
    used       BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS mfa_backup_codes_user_idx ON mfa_backup_codes(user_id);
