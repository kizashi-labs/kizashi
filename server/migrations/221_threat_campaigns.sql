-- Migration 221: User-defined threat campaigns (separate from auto-detected ones)
CREATE TABLE IF NOT EXISTS threat_campaigns (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name         TEXT NOT NULL,
  description  TEXT,
  threat_actor TEXT,
  status       TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','monitoring','inactive')),
  severity     TEXT NOT NULL DEFAULT 'medium' CHECK (severity IN ('critical','high','medium','low')),
  first_seen   TIMESTAMPTZ,
  last_seen    TIMESTAMPTZ,
  ioc_count    INT NOT NULL DEFAULT 0,
  alert_count  INT NOT NULL DEFAULT 0,
  techniques   JSONB NOT NULL DEFAULT '[]',
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_threat_campaigns_status ON threat_campaigns(status, created_at DESC);
