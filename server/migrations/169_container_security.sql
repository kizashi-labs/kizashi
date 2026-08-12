-- 169: container and Kubernetes security
CREATE TABLE IF NOT EXISTS container_images (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    registry TEXT NOT NULL,
    repository TEXT NOT NULL,
    tag TEXT NOT NULL DEFAULT 'latest',
    digest TEXT,
    size_bytes BIGINT,
    vulnerability_count INT NOT NULL DEFAULT 0,
    critical_vulns INT NOT NULL DEFAULT 0,
    high_vulns INT NOT NULL DEFAULT 0,
    scan_status TEXT NOT NULL DEFAULT 'pending' CHECK (scan_status IN ('pending','scanning','scanned','failed')),
    last_scanned_at TIMESTAMPTZ,
    base_image TEXT,
    labels JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(registry, repository, tag)
);
CREATE TABLE IF NOT EXISTS container_runtime_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    container_id TEXT NOT NULL,
    container_name TEXT,
    image TEXT NOT NULL,
    namespace TEXT DEFAULT 'default',
    pod_name TEXT,
    node_name TEXT,
    event_type TEXT NOT NULL DEFAULT 'anomaly' CHECK (event_type IN ('anomaly','privilege_escalation','network_anomaly','file_tampering','crypto_mining','policy_violation')),
    severity TEXT NOT NULL DEFAULT 'medium' CHECK (severity IN ('critical','high','medium','low','info')),
    description TEXT,
    raw_data JSONB DEFAULT '{}',
    alert_id UUID REFERENCES alerts(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_container_images_scan ON container_images(scan_status);
CREATE INDEX IF NOT EXISTS idx_container_images_vulns ON container_images(critical_vulns DESC);
CREATE INDEX IF NOT EXISTS idx_container_events_type ON container_runtime_events(event_type);
CREATE INDEX IF NOT EXISTS idx_container_events_severity ON container_runtime_events(severity);
CREATE INDEX IF NOT EXISTS idx_container_events_created ON container_runtime_events(created_at DESC);
