-- 151: Enhanced Security Automation
CREATE TABLE IF NOT EXISTS automation_triggers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    trigger_type VARCHAR(50) NOT NULL CHECK (trigger_type IN ('alert','schedule','webhook','event','manual')),
    conditions JSONB NOT NULL DEFAULT '{}',
    enabled BOOLEAN DEFAULT true,
    cooldown_seconds INTEGER DEFAULT 300,
    last_fired_at TIMESTAMPTZ,
    fire_count BIGINT DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS automation_actions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    trigger_id UUID REFERENCES automation_triggers(id) ON DELETE CASCADE,
    action_type VARCHAR(50) NOT NULL,
    action_config JSONB NOT NULL DEFAULT '{}',
    order_index INTEGER DEFAULT 0,
    timeout_seconds INTEGER DEFAULT 60,
    on_failure VARCHAR(20) DEFAULT 'continue' CHECK (on_failure IN ('continue','stop','rollback'))
);

CREATE TABLE IF NOT EXISTS automation_runs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    trigger_id UUID REFERENCES automation_triggers(id) ON DELETE SET NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'running' CHECK (status IN ('running','completed','failed','cancelled')),
    action_results JSONB DEFAULT '[]',
    triggered_by VARCHAR(100),
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    duration_ms INTEGER,
    error_message TEXT
);

CREATE INDEX IF NOT EXISTS idx_automation_triggers_tenant ON automation_triggers(tenant_id);
CREATE INDEX IF NOT EXISTS idx_automation_runs_trigger ON automation_runs(trigger_id);
