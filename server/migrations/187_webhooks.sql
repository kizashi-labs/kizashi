-- Migration 187: Webhook configurations and delivery log
CREATE TABLE IF NOT EXISTS webhook_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    url TEXT NOT NULL,
    secret TEXT,
    events TEXT[] DEFAULT '{}',
    platform TEXT DEFAULT 'generic',
    enabled BOOLEAN DEFAULT true,
    retry_count INTEGER DEFAULT 3,
    last_status TEXT,
    last_fired_at TIMESTAMPTZ,
    delivery_count BIGINT DEFAULT 0,
    failure_count BIGINT DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    webhook_id UUID REFERENCES webhook_configs(id) ON DELETE CASCADE,
    event TEXT,
    status TEXT,
    status_code INTEGER,
    response_body TEXT,
    duration_ms INTEGER,
    attempted_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_webhook ON webhook_deliveries(webhook_id, attempted_at DESC);
