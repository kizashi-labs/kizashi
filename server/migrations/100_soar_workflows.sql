CREATE TABLE IF NOT EXISTS soar_workflows (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  trigger_type TEXT NOT NULL DEFAULT 'alert',
  trigger_conditions JSONB NOT NULL DEFAULT '{}',
  actions JSONB NOT NULL DEFAULT '[]',
  enabled BOOL NOT NULL DEFAULT TRUE,
  execution_count INT NOT NULL DEFAULT 0,
  last_executed_at TIMESTAMPTZ,
  created_by UUID,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_soar_workflows_enabled ON soar_workflows(enabled);

CREATE TABLE IF NOT EXISTS soar_executions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workflow_id UUID NOT NULL,
  trigger_event_id UUID,
  trigger_type TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'running',
  actions_completed JSONB NOT NULL DEFAULT '[]',
  error_message TEXT NOT NULL DEFAULT '',
  started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_soar_executions_workflow ON soar_executions(workflow_id);
CREATE INDEX IF NOT EXISTS idx_soar_executions_status ON soar_executions(status);
