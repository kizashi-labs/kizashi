CREATE TABLE IF NOT EXISTS deception_traps (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name         VARCHAR(255) NOT NULL,
  type         VARCHAR(50) NOT NULL,  -- file, registry, network, credential, honeypot
  target_path  TEXT,                  -- file path or registry key
  description  TEXT,
  is_active    BOOLEAN NOT NULL DEFAULT true,
  trigger_count INT NOT NULL DEFAULT 0,
  last_triggered_at TIMESTAMPTZ,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS deception_events (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  trap_id      UUID NOT NULL REFERENCES deception_traps(id) ON DELETE CASCADE,
  endpoint_id  UUID,
  hostname     VARCHAR(255),
  process_name VARCHAR(500),
  process_pid  INT,
  user_name    VARCHAR(255),
  ip_address   INET,
  details      JSONB,
  severity     VARCHAR(50) NOT NULL DEFAULT 'high',
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_deception_events_trap_id ON deception_events(trap_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_deception_events_created ON deception_events(created_at DESC);
