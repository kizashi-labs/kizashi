-- 148: Identity Threat Detection and Response
CREATE TABLE IF NOT EXISTS itdr_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    threat_category VARCHAR(100) NOT NULL,
    detection_logic JSONB NOT NULL DEFAULT '{}',
    severity VARCHAR(20) NOT NULL DEFAULT 'medium',
    mitre_techniques TEXT[] DEFAULT '{}',
    enabled BOOLEAN NOT NULL DEFAULT true,
    hit_count INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS itdr_incidents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id UUID REFERENCES itdr_rules(id) ON DELETE SET NULL,
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    user_id VARCHAR(255) NOT NULL,
    username VARCHAR(255),
    threat_category VARCHAR(100) NOT NULL,
    risk_score NUMERIC(4,2) NOT NULL DEFAULT 0.0,
    severity VARCHAR(20) NOT NULL DEFAULT 'medium',
    indicators JSONB DEFAULT '[]',
    status VARCHAR(20) NOT NULL DEFAULT 'open' CHECK (status IN ('open','investigating','contained','resolved','false_positive')),
    assigned_to VARCHAR(255),
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ,
    notes TEXT
);

CREATE TABLE IF NOT EXISTS itdr_identity_risk (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    user_id VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(255),
    risk_score NUMERIC(4,2) DEFAULT 0.0,
    risk_factors JSONB DEFAULT '[]',
    last_calculated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    privileged BOOLEAN DEFAULT false,
    account_type VARCHAR(50) DEFAULT 'standard'
);

CREATE INDEX IF NOT EXISTS idx_itdr_rules_tenant ON itdr_rules(tenant_id);
CREATE INDEX IF NOT EXISTS idx_itdr_incidents_tenant ON itdr_incidents(tenant_id);
CREATE INDEX IF NOT EXISTS idx_itdr_incidents_user ON itdr_incidents(user_id);
CREATE INDEX IF NOT EXISTS idx_itdr_identity_risk_score ON itdr_identity_risk(risk_score DESC);
