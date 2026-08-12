-- 205: Add compatibility columns to ueba_baselines and ueba_anomalies.
-- 121 created both tables with different column names than what the Go code expects.

-- ueba_baselines: code uses user_key/mean/std_dev/sample_count
ALTER TABLE ueba_baselines ADD COLUMN IF NOT EXISTS user_key     TEXT;
ALTER TABLE ueba_baselines ADD COLUMN IF NOT EXISTS mean         NUMERIC(12,4);
ALTER TABLE ueba_baselines ADD COLUMN IF NOT EXISTS std_dev      NUMERIC(12,4);
ALTER TABLE ueba_baselines ADD COLUMN IF NOT EXISTS sample_count INT NOT NULL DEFAULT 0;

-- Back-fill from existing columns
UPDATE ueba_baselines
   SET user_key     = username,
       mean         = baseline_value,
       std_dev      = std_deviation,
       sample_count = sample_days
 WHERE user_key IS NULL;

-- Unique constraint needed for ON CONFLICT (user_key, metric_name)
CREATE UNIQUE INDEX IF NOT EXISTS idx_ueba_baselines_user_key_metric
    ON ueba_baselines(user_key, metric_name);

-- ueba_anomalies: INSERT uses user_key/agent_id/metric_name/z_score/detected_at
ALTER TABLE ueba_anomalies ADD COLUMN IF NOT EXISTS user_key    TEXT;
ALTER TABLE ueba_anomalies ADD COLUMN IF NOT EXISTS agent_id    UUID;
ALTER TABLE ueba_anomalies ADD COLUMN IF NOT EXISTS metric_name TEXT;
ALTER TABLE ueba_anomalies ADD COLUMN IF NOT EXISTS z_score     NUMERIC(8,4);
ALTER TABLE ueba_anomalies ADD COLUMN IF NOT EXISTS detected_at TIMESTAMPTZ;

-- Back-fill detected_at from created_at for existing rows
UPDATE ueba_anomalies SET user_key = username, detected_at = created_at WHERE detected_at IS NULL;
