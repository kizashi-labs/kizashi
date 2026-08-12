CREATE TABLE IF NOT EXISTS attack_surface_assets (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  asset_type     VARCHAR(100) NOT NULL,  -- domain, ip, port, service, certificate, api_endpoint
  value          VARCHAR(1000) NOT NULL,
  parent_id      UUID REFERENCES attack_surface_assets(id),
  source         VARCHAR(100) NOT NULL DEFAULT 'discovery',  -- discovery, manual, import
  risk_score     INT NOT NULL DEFAULT 0,
  is_known       BOOLEAN NOT NULL DEFAULT false,
  is_monitored   BOOLEAN NOT NULL DEFAULT true,
  tags           JSONB NOT NULL DEFAULT '[]',
  metadata       JSONB NOT NULL DEFAULT '{}',
  first_seen     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_asm_assets_type ON attack_surface_assets(asset_type);
CREATE INDEX IF NOT EXISTS idx_asm_assets_risk ON attack_surface_assets(risk_score DESC);
CREATE TABLE IF NOT EXISTS attack_surface_scans (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_type      VARCHAR(100) NOT NULL,  -- port_scan, dns_enum, cert_check, api_discovery
  target         VARCHAR(500) NOT NULL,
  status         VARCHAR(50) NOT NULL DEFAULT 'pending',
  assets_found   INT NOT NULL DEFAULT 0,
  new_assets     INT NOT NULL DEFAULT 0,
  started_at     TIMESTAMPTZ,
  completed_at   TIMESTAMPTZ,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
