-- Migration 211: Risk Register
-- B-03: Enterprise risk tracking with controls and treatment plans

CREATE TABLE IF NOT EXISTS risk_register (
  id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  risk_id               TEXT NOT NULL DEFAULT '',
  title                 TEXT NOT NULL,
  description           TEXT NOT NULL DEFAULT '',
  category              TEXT NOT NULL DEFAULT 'Technical',
  threat_source         TEXT NOT NULL DEFAULT '',
  vulnerability         TEXT NOT NULL DEFAULT '',
  likelihood            INT NOT NULL DEFAULT 1 CHECK (likelihood BETWEEN 1 AND 5),
  impact                INT NOT NULL DEFAULT 1 CHECK (impact BETWEEN 1 AND 5),
  inherent_risk_score   INT NOT NULL DEFAULT 0,
  controls              JSONB NOT NULL DEFAULT '[]',
  control_effectiveness INT NOT NULL DEFAULT 0 CHECK (control_effectiveness BETWEEN 0 AND 100),
  residual_risk_score   INT NOT NULL DEFAULT 0,
  risk_appetite         TEXT NOT NULL DEFAULT 'within' CHECK (risk_appetite IN ('within','exceeds','at_limit')),
  owner                 TEXT NOT NULL DEFAULT '',
  last_review_date      DATE NOT NULL DEFAULT CURRENT_DATE,
  status                TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','mitigated','transferred','accepted','closed')),
  treatment_plan        JSONB NOT NULL DEFAULT '[]',
  risk_history          JSONB NOT NULL DEFAULT '[]',
  created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_risk_register_status   ON risk_register(status);
CREATE INDEX IF NOT EXISTS idx_risk_register_category ON risk_register(category);
