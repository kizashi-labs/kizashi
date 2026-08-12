CREATE TABLE IF NOT EXISTS honeypots (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  honeypot_type TEXT NOT NULL DEFAULT 'http',
  listen_address TEXT NOT NULL,
  listen_port INT NOT NULL,
  agent_id UUID,
  enabled BOOL NOT NULL DEFAULT TRUE,
  alert_on_access BOOL NOT NULL DEFAULT TRUE,
  access_count INT NOT NULL DEFAULT 0,
  last_accessed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_honeypots_enabled ON honeypots(enabled);

CREATE TABLE IF NOT EXISTS honeypot_accesses (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  honeypot_id UUID NOT NULL,
  source_ip TEXT NOT NULL,
  source_port INT,
  method TEXT,
  path TEXT,
  user_agent TEXT,
  payload TEXT,
  accessed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_honeypot_accesses_honeypot ON honeypot_accesses(honeypot_id, accessed_at DESC);
