CREATE TABLE IF NOT EXISTS user_sessions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    jti         TEXT NOT NULL UNIQUE,  -- JWT ID (blocklist連携)
    device_info JSONB NOT NULL DEFAULT '{}',  -- user_agent, os, browser
    ip_address  INET,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ NOT NULL,
    revoked     BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX idx_sessions_user ON user_sessions(user_id) WHERE NOT revoked;
CREATE INDEX idx_sessions_jti ON user_sessions(jti);
