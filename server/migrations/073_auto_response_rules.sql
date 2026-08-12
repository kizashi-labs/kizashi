CREATE TABLE IF NOT EXISTS auto_response_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    description TEXT DEFAULT '',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    trigger_severity_min INTEGER DEFAULT 7,   -- min alert severity to trigger
    trigger_status TEXT DEFAULT 'open',
    alert_title_pattern TEXT DEFAULT '',       -- regex pattern to match alert title
    action_type TEXT NOT NULL,                 -- isolate_host|kill_process|block_ip|create_ticket|notify_channel
    action_params JSONB DEFAULT '{}',          -- {channel_id, ticket_queue, ip, process_name}
    cooldown_seconds INTEGER DEFAULT 3600,     -- avoid re-triggering too often
    execution_count INTEGER DEFAULT 0,
    last_executed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS auto_response_executions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id UUID NOT NULL REFERENCES auto_response_rules(id) ON DELETE CASCADE,
    alert_id UUID NOT NULL,
    action_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',   -- pending/running/success/failed
    result_msg TEXT DEFAULT '',
    executed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_auto_response_executions_rule ON auto_response_executions(rule_id);
CREATE INDEX IF NOT EXISTS idx_auto_response_executions_alert ON auto_response_executions(alert_id);
