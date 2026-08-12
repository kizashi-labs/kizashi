-- 165: deception technology (honeypots, honeytokens)
CREATE TABLE IF NOT EXISTS deception_assets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL,
    asset_type TEXT NOT NULL DEFAULT 'honeypot' CHECK (asset_type IN ('honeypot','honeytoken','honeyfile','honeycred','honeyuser')),
    description TEXT,
    target_network TEXT,
    emulated_service TEXT,
    listen_port INT,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','inactive','triggered','maintenance')),
    alert_on_access BOOLEAN NOT NULL DEFAULT true,
    deploy_host TEXT,
    configuration JSONB DEFAULT '{}',
    triggered_count INT NOT NULL DEFAULT 0,
    last_triggered TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS deception_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_id UUID REFERENCES deception_assets(id) ON DELETE CASCADE,
    attacker_ip INET,
    attacker_port INT,
    event_type TEXT NOT NULL DEFAULT 'access',
    payload TEXT,
    credentials_used TEXT,
    session_duration_ms INT,
    alert_generated BOOLEAN NOT NULL DEFAULT false,
    alert_id UUID REFERENCES alerts(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
-- 116 created deception_events without asset_id; add before indexing
ALTER TABLE deception_events ADD COLUMN IF NOT EXISTS asset_id UUID REFERENCES deception_assets(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_deception_assets_status ON deception_assets(status);
CREATE INDEX IF NOT EXISTS idx_deception_events_asset ON deception_events(asset_id);
CREATE INDEX IF NOT EXISTS idx_deception_events_created ON deception_events(created_at DESC);
