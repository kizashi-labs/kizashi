-- Migration 220: DNS Security monitoring tables
CREATE TABLE IF NOT EXISTS dns_alerts (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  domain      TEXT NOT NULL,
  query_type  TEXT NOT NULL DEFAULT 'A',
  client_ip   TEXT NOT NULL DEFAULT '',
  agent_id    UUID REFERENCES agents(id) ON DELETE SET NULL,
  threat_type TEXT NOT NULL DEFAULT 'suspicious_domain',
  confidence  INT NOT NULL DEFAULT 70 CHECK (confidence BETWEEN 0 AND 100),
  blocked     BOOLEAN NOT NULL DEFAULT FALSE,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_dns_alerts_created ON dns_alerts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_dns_alerts_domain  ON dns_alerts(domain);

CREATE TABLE IF NOT EXISTS dns_queries (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  domain     TEXT NOT NULL,
  query_type TEXT NOT NULL DEFAULT 'A',
  client_ip  TEXT NOT NULL DEFAULT '',
  agent_id   UUID REFERENCES agents(id) ON DELETE SET NULL,
  category   TEXT NOT NULL DEFAULT 'unknown',
  reputation TEXT NOT NULL DEFAULT 'unknown',
  blocked    BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_dns_queries_created ON dns_queries(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_dns_queries_domain  ON dns_queries(domain);

CREATE TABLE IF NOT EXISTS dns_blocklist (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  domain     TEXT NOT NULL UNIQUE,
  reason     TEXT,
  added_by   TEXT NOT NULL DEFAULT 'system',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Migration 220b: FIM page extensions
CREATE TABLE IF NOT EXISTS fim_events (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id    UUID REFERENCES agents(id) ON DELETE CASCADE,
  file_path   TEXT NOT NULL,
  change_type TEXT NOT NULL DEFAULT 'modified' CHECK (change_type IN ('created','modified','deleted','permissions')),
  risk_score  INT NOT NULL DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_fim_events_agent ON fim_events(agent_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_fim_events_risk  ON fim_events(risk_score DESC);

CREATE TABLE IF NOT EXISTS fim_ignore_rules (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  pattern    TEXT NOT NULL UNIQUE,
  enabled    BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
