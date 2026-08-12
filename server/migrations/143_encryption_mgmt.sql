-- 143: Endpoint Encryption Management
CREATE TABLE IF NOT EXISTS encryption_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    encryption_type VARCHAR(50) NOT NULL CHECK (encryption_type IN ('full_disk','file','folder','removable','email')),
    algorithm VARCHAR(50) NOT NULL DEFAULT 'AES-256',
    key_length INTEGER DEFAULT 256,
    target_scope JSONB DEFAULT '{}',
    enforcement_mode VARCHAR(20) DEFAULT 'enforce',
    enabled BOOLEAN DEFAULT true,
    covered_endpoints INTEGER DEFAULT 0,
    compliance_rate NUMERIC(5,2) DEFAULT 0.0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS encryption_status (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    endpoint_id VARCHAR(255) NOT NULL,
    hostname VARCHAR(255),
    policy_id UUID REFERENCES encryption_policies(id) ON DELETE SET NULL,
    encryption_type VARCHAR(50),
    status VARCHAR(20) NOT NULL DEFAULT 'unknown' CHECK (status IN ('encrypted','partial','unencrypted','unknown','error')),
    algorithm VARCHAR(50),
    key_id VARCHAR(255),
    last_verified_at TIMESTAMPTZ,
    compliance_status VARCHAR(20) DEFAULT 'unknown',
    details JSONB DEFAULT '{}',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_encryption_policies_tenant ON encryption_policies(tenant_id);
CREATE INDEX IF NOT EXISTS idx_encryption_status_endpoint ON encryption_status(endpoint_id);
