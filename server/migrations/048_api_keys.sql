CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    key_prefix TEXT NOT NULL,  -- first 8 chars of raw key for display (e.g. "edr_live")
    key_hash TEXT NOT NULL UNIQUE,  -- SHA-256 hash of full key
    scopes TEXT[] NOT NULL DEFAULT ARRAY['read'],
    -- scopes: 'read', 'write', 'admin'
    last_used_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,  -- NULL = no expiry
    revoked BOOL NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON api_keys(key_hash);
