CREATE TABLE IF NOT EXISTS alert_suppression_rules (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  pattern TEXT NOT NULL,
  match_field TEXT NOT NULL DEFAULT 'title',
  agent_id UUID,
  severity_max INT NOT NULL DEFAULT 10,
  enabled BOOL NOT NULL DEFAULT TRUE,
  expires_at TIMESTAMPTZ,
  suppressed_count INT NOT NULL DEFAULT 0,
  created_by UUID,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_suppression_enabled ON alert_suppression_rules(enabled);
