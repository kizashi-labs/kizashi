-- 137: Supply chain risk management
CREATE TABLE IF NOT EXISTS supply_chain_vendors (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    vendor_type VARCHAR(50) NOT NULL DEFAULT 'software',
    risk_score NUMERIC(4,2) DEFAULT 0.0,
    risk_level VARCHAR(20) NOT NULL DEFAULT 'low' CHECK (risk_level IN ('low','medium','high','critical')),
    criticality VARCHAR(20) NOT NULL DEFAULT 'low',
    contact_email VARCHAR(255),
    assessment_status VARCHAR(50) DEFAULT 'pending',
    last_assessed_at TIMESTAMPTZ,
    next_assessment_at TIMESTAMPTZ,
    sbom JSONB DEFAULT '{}',
    vulnerabilities JSONB DEFAULT '[]',
    compliance_status JSONB DEFAULT '{}',
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS supply_chain_incidents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    vendor_id UUID REFERENCES supply_chain_vendors(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    severity VARCHAR(20) NOT NULL DEFAULT 'medium',
    status VARCHAR(50) NOT NULL DEFAULT 'open',
    impact_assessment JSONB DEFAULT '{}',
    reported_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_supply_chain_vendors_tenant ON supply_chain_vendors(tenant_id);
CREATE INDEX IF NOT EXISTS idx_supply_chain_vendors_risk ON supply_chain_vendors(risk_level);
