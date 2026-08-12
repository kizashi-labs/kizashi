CREATE TABLE IF NOT EXISTS log_parse_rules (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name        VARCHAR(255) NOT NULL,
  description TEXT,
  log_source  VARCHAR(100) NOT NULL,  -- syslog, json, csv, custom
  pattern     TEXT NOT NULL,          -- regex or grok pattern
  field_map   JSONB NOT NULL DEFAULT '{}',
  is_active   BOOLEAN NOT NULL DEFAULT true,
  priority    INT NOT NULL DEFAULT 100,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS log_analysis_jobs (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name        VARCHAR(255) NOT NULL,
  query       TEXT NOT NULL,
  time_range  VARCHAR(50) NOT NULL DEFAULT '1h',
  status      VARCHAR(50) NOT NULL DEFAULT 'pending',
  result_count INT,
  error_msg   TEXT,
  created_by  UUID,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at TIMESTAMPTZ
);
