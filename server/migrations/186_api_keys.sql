-- Migration 186: API Keys table
CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    key_prefix TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    user_id UUID,
    role TEXT DEFAULT 'analyst',
    scopes TEXT[] DEFAULT '{}',
    expires_at TIMESTAMPTZ,
    last_used TIMESTAMPTZ,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys(key_prefix);
CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);
