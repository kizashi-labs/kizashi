CREATE TABLE IF NOT EXISTS agent_certificates (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id   UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  serial     BIGINT NOT NULL UNIQUE,
  thumbprint TEXT NOT NULL,
  issued_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_agent_certs_agent ON agent_certificates(agent_id);
CREATE INDEX IF NOT EXISTS idx_agent_certs_thumbprint ON agent_certificates(thumbprint);
