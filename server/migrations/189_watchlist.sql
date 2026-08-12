CREATE TABLE IF NOT EXISTS watchlist (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    entity_type TEXT NOT NULL,
    entity_value TEXT NOT NULL,
    label TEXT,
    reason TEXT,
    priority INTEGER DEFAULT 3,
    added_by TEXT,
    tags TEXT[] DEFAULT '{}',
    hit_count BIGINT DEFAULT 0,
    last_hit TIMESTAMPTZ,
    enabled BOOLEAN DEFAULT true,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(entity_type, entity_value)
);
CREATE INDEX IF NOT EXISTS idx_watchlist_type_value ON watchlist(entity_type, entity_value);
CREATE INDEX IF NOT EXISTS idx_watchlist_enabled ON watchlist(enabled);
