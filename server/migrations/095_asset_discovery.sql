CREATE TABLE IF NOT EXISTS discovered_assets (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  ip_address TEXT NOT NULL,
  mac_address TEXT NOT NULL DEFAULT '',
  hostname TEXT NOT NULL DEFAULT '',
  vendor TEXT NOT NULL DEFAULT '',
  os_guess TEXT NOT NULL DEFAULT '',
  open_ports JSONB NOT NULL DEFAULT '[]',
  services JSONB NOT NULL DEFAULT '[]',
  device_type TEXT NOT NULL DEFAULT 'unknown',
  is_managed BOOL NOT NULL DEFAULT FALSE,
  agent_id UUID,
  risk_score INT NOT NULL DEFAULT 0,
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(ip_address)
);
CREATE INDEX IF NOT EXISTS idx_discovered_assets_managed ON discovered_assets(is_managed);
CREATE INDEX IF NOT EXISTS idx_discovered_assets_risk ON discovered_assets(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_discovered_assets_last_seen ON discovered_assets(last_seen_at DESC);

CREATE TABLE IF NOT EXISTS discovery_scans (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  subnet TEXT NOT NULL,
  scan_type TEXT NOT NULL DEFAULT 'ping',
  status TEXT NOT NULL DEFAULT 'running',
  assets_found INT NOT NULL DEFAULT 0,
  new_assets INT NOT NULL DEFAULT 0,
  started_by UUID,
  started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at TIMESTAMPTZ
);
