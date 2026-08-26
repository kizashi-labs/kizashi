CREATE TABLE IF NOT EXISTS user_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,  -- SHA-256 hash of the JWT
    ip_address INET,
    user_agent TEXT DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_active_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at TIMESTAMPTZ
);
-- Add columns that 031_sessions.sql did not include
ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS token_hash    TEXT UNIQUE;
ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS user_agent    TEXT DEFAULT '';
ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS last_active_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS revoked_at    TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id ON user_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_user_sessions_token_hash ON user_sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_user_sessions_revoked ON user_sessions(revoked);
