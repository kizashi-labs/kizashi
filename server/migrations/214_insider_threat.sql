-- Migration 214: Insider Threat investigations and behavior events
CREATE TABLE IF NOT EXISTS insider_threat_investigations (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id       TEXT NOT NULL DEFAULT '',
  subject_user  TEXT NOT NULL,
  department    TEXT NOT NULL DEFAULT '',
  investigator  TEXT NOT NULL DEFAULT '',
  opened_date   DATE NOT NULL DEFAULT CURRENT_DATE,
  closed_date   DATE,
  status        TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','in_progress','closed','escalated')),
  risk_level    TEXT NOT NULL DEFAULT 'medium' CHECK (risk_level IN ('critical','high','medium','low')),
  notes         TEXT NOT NULL DEFAULT '',
  risk_indicators JSONB NOT NULL DEFAULT '[]',
  outcome       TEXT CHECK (outcome IN ('confirmed','unconfirmed','false_positive') OR outcome IS NULL),
  priority      TEXT NOT NULL DEFAULT 'medium' CHECK (priority IN ('critical','high','medium','low')),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_insider_inv_status ON insider_threat_investigations(status);
CREATE INDEX IF NOT EXISTS idx_insider_inv_created ON insider_threat_investigations(created_at DESC);

CREATE TABLE IF NOT EXISTS insider_threat_events (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     TEXT NOT NULL DEFAULT '',
  user_name   TEXT NOT NULL,
  department  TEXT NOT NULL DEFAULT '',
  event_type  TEXT NOT NULL DEFAULT 'after_hours_access',
  timestamp   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  severity    TEXT NOT NULL DEFAULT 'medium' CHECK (severity IN ('critical','high','medium','low')),
  description TEXT NOT NULL DEFAULT '',
  details     TEXT NOT NULL DEFAULT '',
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_insider_events_user ON insider_threat_events(user_name);
CREATE INDEX IF NOT EXISTS idx_insider_events_ts ON insider_threat_events(timestamp DESC);

CREATE TABLE IF NOT EXISTS insider_threat_stats (
  id              SERIAL PRIMARY KEY,
  high_risk_users INT NOT NULL DEFAULT 0,
  total_alerts    INT NOT NULL DEFAULT 0,
  open_cases      INT NOT NULL DEFAULT 0,
  data_exfil_attempts INT NOT NULL DEFAULT 0,
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
