CREATE TABLE IF NOT EXISTS cloud_assets (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  provider TEXT NOT NULL,
  asset_type TEXT NOT NULL,
  asset_id TEXT NOT NULL,
  name TEXT NOT NULL,
  region TEXT NOT NULL DEFAULT '',
  account_id TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'active',
  tags JSONB NOT NULL DEFAULT '{}',
  config JSONB NOT NULL DEFAULT '{}',
  risk_score INT NOT NULL DEFAULT 0,
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(provider, asset_id)
);
CREATE INDEX IF NOT EXISTS idx_cloud_assets_provider ON cloud_assets(provider);
CREATE INDEX IF NOT EXISTS idx_cloud_assets_type ON cloud_assets(asset_type);
CREATE INDEX IF NOT EXISTS idx_cloud_assets_risk ON cloud_assets(risk_score DESC);
