-- 146: Network Threat Analytics
CREATE TABLE IF NOT EXISTS nta_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    rule_type VARCHAR(50) NOT NULL DEFAULT 'signature' CHECK (rule_type IN ('signature','behavioral','ml','threshold')),
    protocol VARCHAR(50),
    detection_logic JSONB NOT NULL DEFAULT '{}',
    severity VARCHAR(20) NOT NULL DEFAULT 'medium',
    enabled BOOLEAN NOT NULL DEFAULT true,
    hit_count BIGINT DEFAULT 0,
    false_positive_rate NUMERIC(5,2) DEFAULT 0.0,
    last_triggered_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS nta_detections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id UUID REFERENCES nta_rules(id) ON DELETE SET NULL,
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    src_ip INET,
    dst_ip INET,
    src_port INTEGER,
    dst_port INTEGER,
    protocol VARCHAR(20),
    bytes_sent BIGINT,
    bytes_received BIGINT,
    duration_ms INTEGER,
    threat_type VARCHAR(100),
    severity VARCHAR(20) NOT NULL DEFAULT 'medium',
    confidence NUMERIC(4,2),
    metadata JSONB DEFAULT '{}',
    status VARCHAR(20) NOT NULL DEFAULT 'open' CHECK (status IN ('open','investigating','resolved','false_positive')),
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS nta_baselines (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    entity_type VARCHAR(50) NOT NULL,
    entity_id VARCHAR(255) NOT NULL,
    metric VARCHAR(100) NOT NULL,
    mean_value DOUBLE PRECISION,
    std_dev DOUBLE PRECISION,
    sample_count INTEGER DEFAULT 0,
    last_updated TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, entity_type, entity_id, metric)
);

CREATE INDEX IF NOT EXISTS idx_nta_rules_tenant ON nta_rules(tenant_id);
CREATE INDEX IF NOT EXISTS idx_nta_detections_tenant ON nta_detections(tenant_id);
CREATE INDEX IF NOT EXISTS idx_nta_detections_detected ON nta_detections(detected_at DESC);
