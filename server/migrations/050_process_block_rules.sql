-- Migration 050: Process execution blocking — allow/deny list for process execution on agents.
CREATE TABLE IF NOT EXISTS process_block_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    process_name TEXT NOT NULL,  -- exact name or glob pattern (e.g. "cmd.exe", "pow*")
    rule_type TEXT NOT NULL DEFAULT 'deny' CHECK (rule_type IN ('allow', 'deny')),
    scope TEXT NOT NULL DEFAULT 'all' CHECK (scope IN ('all', 'group', 'agent')),
    scope_id TEXT,  -- group_id or agent_id when scope != 'all'
    action TEXT NOT NULL DEFAULT 'alert' CHECK (action IN ('alert', 'block', 'alert_and_block')),
    enabled BOOL NOT NULL DEFAULT true,
    severity TEXT NOT NULL DEFAULT 'high' CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
