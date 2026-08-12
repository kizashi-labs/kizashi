-- 062_email_verification.sql
-- Add email verification support to users table and create verification tokens table.

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS email_verified    BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS email_verified_at TIMESTAMPTZ;

-- Existing users (pre-migration) are treated as already verified to avoid lockout.
UPDATE users SET email_verified = true, email_verified_at = NOW()
WHERE email_verified = false;

CREATE TABLE IF NOT EXISTS email_verification_tokens (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '24 hours',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_evt_token_hash ON email_verification_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_evt_expires    ON email_verification_tokens(expires_at);
