-- 063_alert_dedup.sql
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS dedup_key TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS dedup_count INTEGER DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_alerts_dedup_key ON alerts(dedup_key) WHERE dedup_key IS NOT NULL;
