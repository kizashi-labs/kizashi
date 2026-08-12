-- Migration 219: Threat Intelligence Platform (TIP) integration configurations
CREATE TABLE IF NOT EXISTS tip_platforms (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name            TEXT NOT NULL,
  platform_key    TEXT NOT NULL UNIQUE,
  status          TEXT NOT NULL DEFAULT 'disconnected' CHECK (status IN ('connected','disconnected','error')),
  last_sync       TIMESTAMPTZ,
  objects_synced  INT NOT NULL DEFAULT 0,
  sync_direction  TEXT NOT NULL DEFAULT 'inbound' CHECK (sync_direction IN ('inbound','outbound','bidirectional')),
  enabled         BOOLEAN NOT NULL DEFAULT FALSE,
  url             TEXT NOT NULL DEFAULT '',
  api_key         TEXT NOT NULL DEFAULT '',
  verify_ssl      BOOLEAN NOT NULL DEFAULT TRUE,
  sync_interval   INT NOT NULL DEFAULT 3600,
  object_types    JSONB NOT NULL DEFAULT '["IOCs"]',
  min_confidence  INT NOT NULL DEFAULT 50,
  tlp_level       TEXT NOT NULL DEFAULT 'amber',
  field_mappings  JSONB NOT NULL DEFAULT '[]',
  stats           JSONB NOT NULL DEFAULT '{}',
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS tip_sync_jobs (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  platform_id      UUID REFERENCES tip_platforms(id) ON DELETE CASCADE,
  platform_name    TEXT NOT NULL DEFAULT '',
  direction        TEXT NOT NULL DEFAULT 'inbound',
  started_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  duration_seconds INT NOT NULL DEFAULT 0,
  objects_in       INT NOT NULL DEFAULT 0,
  objects_out      INT NOT NULL DEFAULT 0,
  status           TEXT NOT NULL DEFAULT 'running' CHECK (status IN ('success','failed','running','partial')),
  errors           INT NOT NULL DEFAULT 0,
  error_message    TEXT,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_tip_jobs_platform ON tip_sync_jobs(platform_id, started_at DESC);
