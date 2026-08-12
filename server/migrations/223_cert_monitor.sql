-- Migration 223: Certificate monitoring table
CREATE TABLE IF NOT EXISTS monitored_certificates (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  domain        TEXT NOT NULL,
  port          INT  NOT NULL DEFAULT 443,
  issuer        TEXT NOT NULL DEFAULT '',
  expires_at    TIMESTAMPTZ,
  status        TEXT NOT NULL DEFAULT 'valid' CHECK (status IN ('valid','expiring_soon','expired','error')),
  last_checked  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_monitored_certs_domain ON monitored_certificates(domain);
