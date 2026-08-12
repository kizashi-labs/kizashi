CREATE TABLE IF NOT EXISTS siem_targets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    type TEXT NOT NULL CHECK (type IN ('syslog_cef', 'splunk_hec', 'elastic_ecs', 'syslog_leef')),
    host TEXT NOT NULL DEFAULT '',
    port INT NOT NULL DEFAULT 514,
    protocol TEXT NOT NULL DEFAULT 'udp' CHECK (protocol IN ('udp', 'tcp', 'https')),
    token TEXT NOT NULL DEFAULT '',         -- Splunk HEC token or API key
    tls_enabled BOOLEAN NOT NULL DEFAULT false,
    index_name TEXT NOT NULL DEFAULT 'main',
    enabled BOOLEAN NOT NULL DEFAULT true,
    min_severity INT NOT NULL DEFAULT 40,   -- 0-100; only forward above this
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_siem_targets_enabled ON siem_targets(enabled);
