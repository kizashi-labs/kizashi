-- 141: Zero Trust Network Access
CREATE TABLE IF NOT EXISTS ztna_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    policy_type VARCHAR(50) NOT NULL DEFAULT 'access' CHECK (policy_type IN ('access','network','device','user')),
    conditions JSONB NOT NULL DEFAULT '{}',
    actions JSONB NOT NULL DEFAULT '{}',
    priority INTEGER NOT NULL DEFAULT 100,
    enabled BOOLEAN NOT NULL DEFAULT true,
    enforcement_mode VARCHAR(20) NOT NULL DEFAULT 'enforce' CHECK (enforcement_mode IN ('enforce','monitor','disabled')),
    hit_count BIGINT DEFAULT 0,
    last_triggered_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ztna_access_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id UUID REFERENCES ztna_policies(id) ON DELETE SET NULL,
    user_id VARCHAR(255),
    device_id VARCHAR(255),
    source_ip INET,
    destination VARCHAR(255),
    resource VARCHAR(255),
    action VARCHAR(20) NOT NULL,
    decision VARCHAR(20) NOT NULL CHECK (decision IN ('allow','deny','challenge')),
    risk_score NUMERIC(4,2),
    context JSONB DEFAULT '{}',
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ztna_device_posture (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id VARCHAR(255) UNIQUE NOT NULL,
    hostname VARCHAR(255),
    os_type VARCHAR(50),
    os_version VARCHAR(100),
    compliance_score NUMERIC(4,2) DEFAULT 0.0,
    checks JSONB DEFAULT '[]',
    last_checked_at TIMESTAMPTZ,
    status VARCHAR(20) NOT NULL DEFAULT 'unknown' CHECK (status IN ('compliant','non-compliant','unknown','pending'))
);

CREATE INDEX IF NOT EXISTS idx_ztna_policies_tenant ON ztna_policies(tenant_id);
CREATE INDEX IF NOT EXISTS idx_ztna_access_logs_timestamp ON ztna_access_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_ztna_device_posture_device ON ztna_device_posture(device_id);
