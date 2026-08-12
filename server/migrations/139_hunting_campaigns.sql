-- 139: Threat hunting campaigns
CREATE TABLE IF NOT EXISTS hunting_campaigns (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    hypothesis TEXT,
    tactic VARCHAR(100),
    techniques TEXT[] DEFAULT '{}',
    status VARCHAR(20) NOT NULL DEFAULT 'planning' CHECK (status IN ('planning','active','paused','completed','archived')),
    priority VARCHAR(20) NOT NULL DEFAULT 'medium',
    assigned_analysts TEXT[] DEFAULT '{}',
    start_date DATE,
    end_date DATE,
    queries JSONB DEFAULT '[]',
    findings JSONB DEFAULT '[]',
    iocs_discovered INTEGER DEFAULT 0,
    hosts_investigated INTEGER DEFAULT 0,
    conclusion TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS hunting_campaign_notes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    campaign_id UUID REFERENCES hunting_campaigns(id) ON DELETE CASCADE,
    author VARCHAR(255) NOT NULL,
    content TEXT NOT NULL,
    note_type VARCHAR(50) DEFAULT 'observation',
    attachments JSONB DEFAULT '[]',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_hunting_campaigns_tenant ON hunting_campaigns(tenant_id);
CREATE INDEX IF NOT EXISTS idx_hunting_campaigns_status ON hunting_campaigns(status);
