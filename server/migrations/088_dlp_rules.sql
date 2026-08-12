CREATE TABLE IF NOT EXISTS dlp_rules (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  pattern TEXT NOT NULL,
  pattern_type TEXT NOT NULL DEFAULT 'regex',
  data_category TEXT NOT NULL DEFAULT 'pii',
  action TEXT NOT NULL DEFAULT 'alert',
  severity INT NOT NULL DEFAULT 7,
  enabled BOOL NOT NULL DEFAULT TRUE,
  match_count INT NOT NULL DEFAULT 0,
  created_by UUID,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS dlp_violations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  rule_id UUID NOT NULL,
  agent_id UUID NOT NULL,
  file_path TEXT,
  process_name TEXT,
  matched_pattern TEXT NOT NULL,
  action_taken TEXT NOT NULL,
  detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_dlp_violations_rule ON dlp_violations(rule_id);
CREATE INDEX IF NOT EXISTS idx_dlp_violations_agent ON dlp_violations(agent_id);
CREATE INDEX IF NOT EXISTS idx_dlp_violations_time ON dlp_violations(detected_at DESC);
