CREATE TABLE IF NOT EXISTS remediation_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    enabled BOOLEAN DEFAULT true,
    trigger_config JSONB NOT NULL DEFAULT '{}',
    actions JSONB NOT NULL DEFAULT '[]',
    cooldown_seconds INTEGER DEFAULT 300,
    execution_count INTEGER DEFAULT 0,
    last_executed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS remediation_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id UUID REFERENCES remediation_rules(id),
    rule_name TEXT,
    trigger_id TEXT,
    agent_id UUID,
    actions_result JSONB DEFAULT '[]',
    status TEXT DEFAULT 'success',
    executed_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_remediation_logs_executed ON remediation_logs(executed_at DESC);
CREATE INDEX IF NOT EXISTS idx_remediation_logs_rule ON remediation_logs(rule_id);
