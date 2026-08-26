-- 168: API security monitoring
CREATE TABLE IF NOT EXISTS api_endpoints (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    service_name TEXT NOT NULL,
    method TEXT NOT NULL CHECK (method IN ('GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS')),
    path TEXT NOT NULL,
    description TEXT,
    auth_required BOOLEAN NOT NULL DEFAULT true,
    rate_limit_per_min INT DEFAULT 60,
    risk_level TEXT NOT NULL DEFAULT 'low' CHECK (risk_level IN ('critical','high','medium','low')),
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(service_name, method, path)
);
CREATE TABLE IF NOT EXISTS api_security_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    endpoint_id UUID REFERENCES api_endpoints(id) ON DELETE SET NULL,
    event_type TEXT NOT NULL DEFAULT 'anomaly' CHECK (event_type IN ('anomaly','rate_limit','auth_failure','injection','unauthorized','scraping')),
    source_ip INET,
    user_agent TEXT,
    request_count INT DEFAULT 1,
    status_code INT,
    payload_snippet TEXT,
    risk_score INT DEFAULT 0,
    alert_id UUID REFERENCES alerts(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_api_events_endpoint ON api_security_events(endpoint_id);
CREATE INDEX IF NOT EXISTS idx_api_events_type ON api_security_events(event_type);
CREATE INDEX IF NOT EXISTS idx_api_events_created ON api_security_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_api_events_source ON api_security_events(source_ip);
