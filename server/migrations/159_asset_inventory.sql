-- 159: asset inventory
CREATE TABLE IF NOT EXISTS asset_inventory (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id UUID REFERENCES agents(id) ON DELETE SET NULL,
    asset_type TEXT NOT NULL DEFAULT 'endpoint' CHECK (asset_type IN ('endpoint','server','network','cloud','mobile','iot','other')),
    name TEXT NOT NULL,
    ip_addresses INET[] DEFAULT '{}',
    mac_addresses TEXT[] DEFAULT '{}',
    os_name TEXT,
    os_version TEXT,
    department TEXT,
    owner TEXT,
    criticality TEXT NOT NULL DEFAULT 'medium' CHECK (criticality IN ('critical','high','medium','low')),
    tags TEXT[] DEFAULT '{}',
    metadata JSONB DEFAULT '{}',
    last_seen TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_asset_agent ON asset_inventory(agent_id);
CREATE INDEX IF NOT EXISTS idx_asset_type ON asset_inventory(asset_type);
CREATE INDEX IF NOT EXISTS idx_asset_criticality ON asset_inventory(criticality);
