-- 138: Enhanced orchestration
CREATE TABLE IF NOT EXISTS orchestration_workflows (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    trigger_type VARCHAR(50) NOT NULL DEFAULT 'manual',
    trigger_config JSONB DEFAULT '{}',
    steps JSONB NOT NULL DEFAULT '[]',
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    execution_count INTEGER DEFAULT 0,
    success_count INTEGER DEFAULT 0,
    failure_count INTEGER DEFAULT 0,
    avg_duration_seconds INTEGER DEFAULT 0,
    last_executed_at TIMESTAMPTZ,
    created_by VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS orchestration_executions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workflow_id UUID REFERENCES orchestration_workflows(id) ON DELETE CASCADE,
    status VARCHAR(20) NOT NULL DEFAULT 'running',
    triggered_by VARCHAR(100),
    trigger_context JSONB DEFAULT '{}',
    step_results JSONB DEFAULT '[]',
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    duration_seconds INTEGER,
    error_message TEXT
);

CREATE INDEX IF NOT EXISTS idx_orch_workflows_tenant ON orchestration_workflows(tenant_id);
CREATE INDEX IF NOT EXISTS idx_orch_executions_workflow ON orchestration_executions(workflow_id);
