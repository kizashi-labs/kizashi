-- Migration 216: Network anomaly detections table
CREATE TABLE IF NOT EXISTS network_anomalies (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  type             TEXT NOT NULL DEFAULT 'traffic_spike',
  agent_id         TEXT NOT NULL DEFAULT '',
  agent_hostname   TEXT NOT NULL DEFAULT '',
  description      TEXT NOT NULL DEFAULT '',
  severity         TEXT NOT NULL DEFAULT 'medium' CHECK (severity IN ('critical','high','medium','low')),
  source_ip        TEXT NOT NULL DEFAULT '',
  source_port      INT,
  dest_ip          TEXT,
  dest_port        INT,
  bytes_transferred BIGINT,
  related_alert_id TEXT,
  suppressed       BOOLEAN NOT NULL DEFAULT FALSE,
  detected_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_net_anomalies_detected ON network_anomalies(detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_net_anomalies_agent ON network_anomalies(agent_id);
CREATE INDEX IF NOT EXISTS idx_net_anomalies_type ON network_anomalies(type);
