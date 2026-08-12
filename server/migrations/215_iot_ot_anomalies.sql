-- Migration 215: IoT/OT anomaly alerts
CREATE TABLE IF NOT EXISTS iot_ot_anomalies (
  id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id            TEXT NOT NULL DEFAULT '',
  device_name          TEXT NOT NULL DEFAULT '',
  anomaly_type         TEXT NOT NULL DEFAULT 'unusual_protocol',
  severity             TEXT NOT NULL DEFAULT 'medium' CHECK (severity IN ('critical','high','medium','low')),
  description          TEXT NOT NULL DEFAULT '',
  status               TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','investigating','resolved','false_positive')),
  protocol_context     TEXT NOT NULL DEFAULT '',
  recommended_response TEXT NOT NULL DEFAULT '',
  timestamp            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_iot_anomalies_ts ON iot_ot_anomalies(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_iot_anomalies_device ON iot_ot_anomalies(device_id);

-- Extend iot_devices with OT-specific columns if missing
ALTER TABLE iot_devices ADD COLUMN IF NOT EXISTS protocol         TEXT NOT NULL DEFAULT 'HTTP';
ALTER TABLE iot_devices ADD COLUMN IF NOT EXISTS network_zone     TEXT NOT NULL DEFAULT 'IoT';
ALTER TABLE iot_devices ADD COLUMN IF NOT EXISTS patch_status     TEXT NOT NULL DEFAULT 'unknown';
ALTER TABLE iot_devices ADD COLUMN IF NOT EXISTS known_vulns      JSONB NOT NULL DEFAULT '[]';
ALTER TABLE iot_devices ADD COLUMN IF NOT EXISTS communicates_with JSONB NOT NULL DEFAULT '[]';
ALTER TABLE iot_devices ADD COLUMN IF NOT EXISTS hardening_steps  JSONB NOT NULL DEFAULT '[]';
