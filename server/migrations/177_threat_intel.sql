CREATE TABLE IF NOT EXISTS threat_intel_feeds (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    feed_type TEXT NOT NULL,
    url TEXT,
    api_key TEXT,
    enabled BOOLEAN DEFAULT true,
    last_fetch TIMESTAMPTZ,
    fetch_interval_min INTEGER DEFAULT 60,
    ioc_count INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS threat_intel_iocs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ioc_type TEXT NOT NULL,
    value TEXT NOT NULL,
    confidence INTEGER DEFAULT 50,
    severity INTEGER DEFAULT 5,
    source TEXT,
    tags TEXT[] DEFAULT '{}',
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(ioc_type, value)
);
CREATE INDEX IF NOT EXISTS idx_threat_intel_iocs_value ON threat_intel_iocs(value);
CREATE INDEX IF NOT EXISTS idx_threat_intel_iocs_type ON threat_intel_iocs(ioc_type);
