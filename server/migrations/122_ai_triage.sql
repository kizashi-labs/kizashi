CREATE TABLE IF NOT EXISTS ai_triage_rules (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name           VARCHAR(255) NOT NULL,
  description    TEXT,
  conditions     JSONB NOT NULL DEFAULT '[]',  -- array of {field, operator, value} conditions
  action         VARCHAR(100) NOT NULL,  -- auto_close, escalate, assign, tag, suppress
  action_params  JSONB NOT NULL DEFAULT '{}',
  priority       INT NOT NULL DEFAULT 100,
  is_active      BOOLEAN NOT NULL DEFAULT true,
  match_count    INT NOT NULL DEFAULT 0,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS ai_triage_results (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  alert_id       UUID NOT NULL,
  rule_id        UUID REFERENCES ai_triage_rules(id),
  confidence     NUMERIC(4,2) NOT NULL,
  suggested_action VARCHAR(100) NOT NULL,
  reasoning      TEXT,
  model_version  VARCHAR(50) NOT NULL DEFAULT 'v1.0',
  was_accepted   BOOLEAN,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_triage_results_alert ON ai_triage_results(alert_id);
