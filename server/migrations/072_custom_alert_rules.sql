CREATE TABLE IF NOT EXISTS custom_alert_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    description TEXT DEFAULT '',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    event_type TEXT NOT NULL,         -- process_event/network_connection/file_event/dns_query
    conditions JSONB NOT NULL DEFAULT '[]',  -- [{field, operator, value}]
    threshold_count INTEGER NOT NULL DEFAULT 1,
    time_window_seconds INTEGER NOT NULL DEFAULT 300,
    severity INTEGER NOT NULL DEFAULT 5 CHECK (severity BETWEEN 1 AND 10),
    alert_title TEXT NOT NULL,
    alert_description TEXT DEFAULT '',
    mitre_tags TEXT[] DEFAULT '{}',
    created_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_custom_alert_rules_enabled ON custom_alert_rules(enabled);
CREATE INDEX IF NOT EXISTS idx_custom_alert_rules_event_type ON custom_alert_rules(event_type);
