-- 145: Security Governance
CREATE TABLE IF NOT EXISTS governance_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    policy_number VARCHAR(100),
    category VARCHAR(100) NOT NULL,
    version VARCHAR(20) NOT NULL DEFAULT '1.0',
    status VARCHAR(20) NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','review','approved','published','retired')),
    owner VARCHAR(255),
    approver VARCHAR(255),
    content TEXT,
    effective_date DATE,
    review_date DATE,
    frameworks TEXT[] DEFAULT '{}',
    related_controls TEXT[] DEFAULT '{}',
    acknowledgment_required BOOLEAN DEFAULT false,
    acknowledged_count INTEGER DEFAULT 0,
    total_staff INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS governance_exceptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id UUID REFERENCES governance_policies(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    justification TEXT NOT NULL,
    risk_level VARCHAR(20) NOT NULL DEFAULT 'medium',
    compensating_controls TEXT,
    requestor VARCHAR(255),
    approver VARCHAR(255),
    status VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','rejected','expired')),
    valid_until DATE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_governance_policies_tenant ON governance_policies(tenant_id);
CREATE INDEX IF NOT EXISTS idx_governance_policies_status ON governance_policies(status);
CREATE INDEX IF NOT EXISTS idx_governance_exceptions_policy ON governance_exceptions(policy_id);
