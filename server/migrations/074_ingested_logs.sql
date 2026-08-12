CREATE TABLE IF NOT EXISTS ingested_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_name TEXT NOT NULL,
    source_ip INET,
    format TEXT NOT NULL DEFAULT 'json',  -- json/syslog/cef
    raw_data TEXT NOT NULL,
    parsed_data JSONB,
    event_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    processed BOOLEAN NOT NULL DEFAULT FALSE,
    error_msg TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_ingested_logs_source ON ingested_logs(source_name);
CREATE INDEX IF NOT EXISTS idx_ingested_logs_event_time ON ingested_logs(event_time);
CREATE INDEX IF NOT EXISTS idx_ingested_logs_processed ON ingested_logs(processed);

CREATE TABLE IF NOT EXISTS log_sources (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL UNIQUE,
    description TEXT DEFAULT '',
    format TEXT NOT NULL DEFAULT 'json',
    token TEXT NOT NULL DEFAULT gen_random_uuid()::text,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    total_ingested BIGINT DEFAULT 0,
    last_received_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
