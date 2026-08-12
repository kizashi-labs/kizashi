CREATE TABLE IF NOT EXISTS ueba_baselines (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id        UUID,
  username       VARCHAR(255) NOT NULL,
  metric_name    VARCHAR(100) NOT NULL,  -- daily_login_count, avg_login_hour, data_access_gb, unique_hosts, etc.
  baseline_value NUMERIC(12,4) NOT NULL,
  std_deviation  NUMERIC(12,4) NOT NULL DEFAULT 0,
  sample_days    INT NOT NULL DEFAULT 30,
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(username, metric_name)
);
CREATE TABLE IF NOT EXISTS ueba_anomalies (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  username       VARCHAR(255) NOT NULL,
  anomaly_type   VARCHAR(100) NOT NULL,
  severity       VARCHAR(50) NOT NULL DEFAULT 'medium',
  score          NUMERIC(6,2) NOT NULL,
  baseline_value NUMERIC(12,4),
  actual_value   NUMERIC(12,4),
  description    TEXT,
  details        JSONB NOT NULL DEFAULT '{}',
  status         VARCHAR(50) NOT NULL DEFAULT 'open',  -- open, reviewed, false_positive, confirmed
  reviewed_by    UUID,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_ueba_anomalies_user ON ueba_anomalies(username, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ueba_anomalies_created ON ueba_anomalies(created_at DESC);
