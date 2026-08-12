CREATE TABLE IF NOT EXISTS siem_log_sources (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name           VARCHAR(255) NOT NULL,
  source_type    VARCHAR(100) NOT NULL,  -- cloudwatch, stackdriver, azure_monitor, s3, kafka, syslog
  config         JSONB NOT NULL DEFAULT '{}',
  is_active      BOOLEAN NOT NULL DEFAULT true,
  daily_volume_mb BIGINT NOT NULL DEFAULT 0,
  last_received  TIMESTAMPTZ,
  error_count    INT NOT NULL DEFAULT 0,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS siem_detection_rules (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name           VARCHAR(255) NOT NULL,
  description    TEXT,
  rule_type      VARCHAR(100) NOT NULL,  -- threshold, sequence, anomaly, correlation
  query          TEXT NOT NULL,
  severity       VARCHAR(50) NOT NULL DEFAULT 'medium',
  time_window    INT NOT NULL DEFAULT 300,  -- seconds
  threshold      INT,
  is_active      BOOLEAN NOT NULL DEFAULT true,
  match_count    INT NOT NULL DEFAULT 0,
  last_matched   TIMESTAMPTZ,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS siem_queries (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name           VARCHAR(255) NOT NULL,
  description    TEXT,
  query          TEXT NOT NULL,
  is_saved       BOOLEAN NOT NULL DEFAULT true,
  run_count      INT NOT NULL DEFAULT 0,
  created_by     UUID,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
