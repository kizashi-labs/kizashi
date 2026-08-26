-- Migration 181: SIEM connector configurations
CREATE TABLE IF NOT EXISTS siem_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    siem_type TEXT NOT NULL,
    url TEXT NOT NULL,
    api_key TEXT,
    index_name TEXT,
    enabled BOOLEAN DEFAULT true,
    format TEXT DEFAULT 'json',
    batch_size INTEGER DEFAULT 100,
    last_sent TIMESTAMPTZ,
    sent_count BIGINT DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
