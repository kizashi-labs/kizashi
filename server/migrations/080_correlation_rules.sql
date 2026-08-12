CREATE TABLE IF NOT EXISTS correlation_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    description TEXT DEFAULT '',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    trigger_event_type TEXT NOT NULL,    -- process_event/network/alert/fim
    follow_event_type TEXT NOT NULL,     -- event to look for after trigger
    time_window_seconds INTEGER NOT NULL DEFAULT 300,
    same_agent BOOLEAN NOT NULL DEFAULT TRUE,
    trigger_conditions JSONB DEFAULT '[]',
    follow_conditions JSONB DEFAULT '[]',
    alert_title TEXT NOT NULL,
    alert_severity INTEGER NOT NULL DEFAULT 7,
    cooldown_seconds INTEGER DEFAULT 3600,
    match_count INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
