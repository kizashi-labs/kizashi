-- 162: incident response playbooks
CREATE TABLE IF NOT EXISTS incident_playbooks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL,
    description TEXT,
    trigger_type TEXT NOT NULL DEFAULT 'manual' CHECK (trigger_type IN ('manual','alert','scheduled','webhook')),
    trigger_conditions JSONB DEFAULT '{}',
    steps JSONB NOT NULL DEFAULT '[]',
    category TEXT NOT NULL DEFAULT 'general',
    enabled BOOLEAN NOT NULL DEFAULT true,
    run_count INT NOT NULL DEFAULT 0,
    last_run_at TIMESTAMPTZ,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS playbook_executions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    playbook_id UUID REFERENCES incident_playbooks(id) ON DELETE CASCADE,
    alert_id UUID REFERENCES alerts(id) ON DELETE SET NULL,
    triggered_by UUID REFERENCES users(id) ON DELETE SET NULL,
    status TEXT NOT NULL DEFAULT 'running' CHECK (status IN ('running','completed','failed','cancelled')),
    current_step INT NOT NULL DEFAULT 0,
    results JSONB DEFAULT '[]',
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
-- 086 created playbook_executions without created_at, alert_id, triggered_by, current_step, results
ALTER TABLE playbook_executions ADD COLUMN IF NOT EXISTS created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW();
ALTER TABLE playbook_executions ADD COLUMN IF NOT EXISTS alert_id      UUID REFERENCES alerts(id) ON DELETE SET NULL;
ALTER TABLE playbook_executions ADD COLUMN IF NOT EXISTS triggered_by  UUID REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE playbook_executions ADD COLUMN IF NOT EXISTS current_step  INT NOT NULL DEFAULT 0;
ALTER TABLE playbook_executions ADD COLUMN IF NOT EXISTS results       JSONB DEFAULT '[]';

CREATE INDEX IF NOT EXISTS idx_pb_exec_playbook ON playbook_executions(playbook_id);
CREATE INDEX IF NOT EXISTS idx_pb_exec_status ON playbook_executions(status);
CREATE INDEX IF NOT EXISTS idx_pb_exec_created ON playbook_executions(created_at DESC);
