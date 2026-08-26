-- Migration 222: Dark web monitoring tables
CREATE TABLE IF NOT EXISTS dark_web_findings (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  finding_type  TEXT NOT NULL DEFAULT 'mention' CHECK (finding_type IN ('credential','mention','data_leak','domain_spoof')),
  title         TEXT NOT NULL,
  source        TEXT NOT NULL DEFAULT '',
  severity      TEXT NOT NULL DEFAULT 'medium' CHECK (severity IN ('critical','high','medium','low')),
  preview       TEXT,
  status        TEXT NOT NULL DEFAULT 'new' CHECK (status IN ('new','investigating','resolved')),
  discovered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_dark_web_findings_discovered ON dark_web_findings(discovered_at DESC);

CREATE TABLE IF NOT EXISTS dark_web_keywords (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  keyword         TEXT NOT NULL UNIQUE,
  category        TEXT NOT NULL DEFAULT 'brand' CHECK (category IN ('domain','email','brand','executive')),
  enabled         BOOLEAN NOT NULL DEFAULT TRUE,
  last_match_date TIMESTAMPTZ,
  match_count     INT NOT NULL DEFAULT 0,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
