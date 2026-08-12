CREATE TABLE IF NOT EXISTS webhook_targets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    url TEXT NOT NULL,
    secret TEXT,  -- HMAC-SHA256 signing secret (optional)
    events TEXT[] NOT NULL DEFAULT ARRAY['alert.critical'],
    -- events: 'alert.critical', 'alert.high', 'alert.any', 'incident.created', 'incident.updated', 'agent.offline'
    enabled BOOL NOT NULL DEFAULT true,
    last_triggered_at TIMESTAMPTZ,
    last_status INT,  -- HTTP response code from last delivery
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
