CREATE TABLE IF NOT EXISTS yara_rules (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  rule_content TEXT NOT NULL,
  category TEXT NOT NULL DEFAULT 'malware',
  severity INT NOT NULL DEFAULT 5 CHECK (severity BETWEEN 1 AND 10),
  enabled BOOL NOT NULL DEFAULT TRUE,
  last_scan_at TIMESTAMPTZ,
  match_count INT NOT NULL DEFAULT 0,
  created_by UUID,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
-- 041 created yara_rules without category, rule_content, last_scan_at, match_count
ALTER TABLE yara_rules ADD COLUMN IF NOT EXISTS category     TEXT NOT NULL DEFAULT 'malware';
ALTER TABLE yara_rules ADD COLUMN IF NOT EXISTS rule_content TEXT;
ALTER TABLE yara_rules ADD COLUMN IF NOT EXISTS last_scan_at TIMESTAMPTZ;
ALTER TABLE yara_rules ADD COLUMN IF NOT EXISTS match_count  INT NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_yara_rules_enabled ON yara_rules(enabled);
CREATE INDEX IF NOT EXISTS idx_yara_rules_category ON yara_rules(category);

CREATE TABLE IF NOT EXISTS yara_scan_results (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  rule_id UUID NOT NULL,
  agent_id UUID NOT NULL,
  file_path TEXT NOT NULL,
  matched_strings JSONB NOT NULL DEFAULT '[]',
  scanned_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_yara_results_rule ON yara_scan_results(rule_id);
CREATE INDEX IF NOT EXISTS idx_yara_results_agent ON yara_scan_results(agent_id);
