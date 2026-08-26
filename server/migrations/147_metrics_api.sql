-- 147: Security Metrics API
CREATE TABLE IF NOT EXISTS metrics_definitions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    description TEXT,
    category VARCHAR(100) NOT NULL,
    unit VARCHAR(50),
    aggregation VARCHAR(50) NOT NULL DEFAULT 'avg' CHECK (aggregation IN ('avg','sum','count','min','max','p50','p95','p99')),
    query_template TEXT,
    thresholds JSONB DEFAULT '{}',
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS metrics_snapshots (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    metric_id UUID REFERENCES metrics_definitions(id) ON DELETE CASCADE,
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    value DOUBLE PRECISION NOT NULL,
    labels JSONB DEFAULT '{}',
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_metrics_defs_tenant ON metrics_definitions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_metrics_snapshots_metric ON metrics_snapshots(metric_id, recorded_at DESC);
CREATE INDEX IF NOT EXISTS idx_metrics_snapshots_recorded ON metrics_snapshots(recorded_at DESC);
