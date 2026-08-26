CREATE TABLE IF NOT EXISTS ransomware_protection_config (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  enabled           BOOLEAN NOT NULL DEFAULT true,
  protected_folders JSONB NOT NULL DEFAULT '[]',
  allowed_apps      JSONB NOT NULL DEFAULT '[]',
  backup_enabled    BOOLEAN NOT NULL DEFAULT true,
  backup_interval_hours INT NOT NULL DEFAULT 4,
  canary_files_enabled BOOLEAN NOT NULL DEFAULT true,
  canary_file_paths JSONB NOT NULL DEFAULT '[]',
  entropy_detection  BOOLEAN NOT NULL DEFAULT true,
  entropy_threshold  NUMERIC(4,2) NOT NULL DEFAULT 7.5,
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS ransomware_events (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  endpoint_id    UUID,
  hostname       VARCHAR(255),
  event_type     VARCHAR(100) NOT NULL,  -- canary_triggered, high_entropy, mass_rename, shadow_delete
  process_name   VARCHAR(500),
  process_pid    INT,
  affected_files INT,
  details        JSONB,
  auto_isolated  BOOLEAN NOT NULL DEFAULT false,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_ransomware_events_created ON ransomware_events(created_at DESC);
