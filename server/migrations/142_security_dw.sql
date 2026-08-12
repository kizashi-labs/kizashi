-- 142: Security Data Warehouse
CREATE TABLE IF NOT EXISTS security_dw_datasets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    source_type VARCHAR(50) NOT NULL,
    source_config JSONB DEFAULT '{}',
    schema_definition JSONB DEFAULT '{}',
    retention_days INTEGER DEFAULT 365,
    compression_enabled BOOLEAN DEFAULT true,
    row_count BIGINT DEFAULT 0,
    size_bytes BIGINT DEFAULT 0,
    last_ingested_at TIMESTAMPTZ,
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS security_dw_queries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255),
    query_text TEXT NOT NULL,
    dataset_ids UUID[] DEFAULT '{}',
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    rows_returned BIGINT,
    execution_ms INTEGER,
    result_preview JSONB,
    created_by VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_security_dw_datasets_tenant ON security_dw_datasets(tenant_id);
CREATE INDEX IF NOT EXISTS idx_security_dw_queries_tenant ON security_dw_queries(tenant_id);
