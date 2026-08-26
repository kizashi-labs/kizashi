CREATE TABLE IF NOT EXISTS oauth2_clients (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  client_id TEXT NOT NULL UNIQUE,
  client_secret_hash TEXT NOT NULL,
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  redirect_uris JSONB NOT NULL DEFAULT '[]',
  allowed_scopes JSONB NOT NULL DEFAULT '["read"]',
  grant_types JSONB NOT NULL DEFAULT '["authorization_code"]',
  is_confidential BOOL NOT NULL DEFAULT TRUE,
  enabled BOOL NOT NULL DEFAULT TRUE,
  created_by UUID,
  last_used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_oauth2_client_id ON oauth2_clients(client_id);
