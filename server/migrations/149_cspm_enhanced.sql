-- 149: Enhanced Cloud Security Posture Management
CREATE TABLE IF NOT EXISTS cspm_accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    cloud_provider VARCHAR(20) NOT NULL CHECK (cloud_provider IN ('aws','azure','gcp','alibaba')),
    account_id VARCHAR(255) NOT NULL,
    account_name VARCHAR(255) NOT NULL,
    regions TEXT[] DEFAULT '{}',
    posture_score NUMERIC(4,2) DEFAULT 0.0,
    critical_findings INTEGER DEFAULT 0,
    high_findings INTEGER DEFAULT 0,
    last_scanned_at TIMESTAMPTZ,
    scan_status VARCHAR(20) DEFAULT 'idle',
    credentials_arn VARCHAR(500),
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS cspm_findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id UUID REFERENCES cspm_accounts(id) ON DELETE CASCADE,
    resource_type VARCHAR(100) NOT NULL,
    resource_id VARCHAR(500) NOT NULL,
    resource_name VARCHAR(255),
    region VARCHAR(100),
    check_id VARCHAR(100) NOT NULL,
    check_name VARCHAR(255) NOT NULL,
    severity VARCHAR(20) NOT NULL DEFAULT 'medium',
    status VARCHAR(20) NOT NULL DEFAULT 'open' CHECK (status IN ('open','suppressed','resolved','accepted_risk')),
    description TEXT,
    remediation TEXT,
    compliance_frameworks TEXT[] DEFAULT '{}',
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cspm_accounts_tenant ON cspm_accounts(tenant_id);
CREATE INDEX IF NOT EXISTS idx_cspm_findings_account ON cspm_findings(account_id);
CREATE INDEX IF NOT EXISTS idx_cspm_findings_severity ON cspm_findings(severity);
CREATE INDEX IF NOT EXISTS idx_cspm_findings_status ON cspm_findings(status);
