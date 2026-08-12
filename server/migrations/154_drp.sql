-- 154: Digital Risk Protection
CREATE TABLE IF NOT EXISTS drp_monitors (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    monitor_type VARCHAR(50) NOT NULL CHECK (monitor_type IN ('brand','domain','credential','executive','data_leak','social_media','dark_web')),
    keywords TEXT[] DEFAULT '{}',
    domains TEXT[] DEFAULT '{}',
    enabled BOOLEAN DEFAULT true,
    alert_threshold VARCHAR(20) DEFAULT 'medium',
    last_scanned_at TIMESTAMPTZ,
    findings_count INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS drp_findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    monitor_id UUID REFERENCES drp_monitors(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    source VARCHAR(100),
    source_url TEXT,
    content_preview TEXT,
    severity VARCHAR(20) NOT NULL DEFAULT 'medium',
    status VARCHAR(20) NOT NULL DEFAULT 'open' CHECK (status IN ('open','investigating','mitigated','false_positive','accepted')),
    found_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata JSONB DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_drp_monitors_tenant ON drp_monitors(tenant_id);
CREATE INDEX IF NOT EXISTS idx_drp_findings_monitor ON drp_findings(monitor_id);
CREATE INDEX IF NOT EXISTS idx_drp_findings_severity ON drp_findings(severity);
