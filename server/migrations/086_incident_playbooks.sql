CREATE TABLE IF NOT EXISTS incident_playbooks (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  incident_type TEXT NOT NULL DEFAULT 'general',
  severity_threshold INT NOT NULL DEFAULT 5,
  steps JSONB NOT NULL DEFAULT '[]',
  auto_assign BOOL NOT NULL DEFAULT FALSE,
  enabled BOOL NOT NULL DEFAULT TRUE,
  usage_count INT NOT NULL DEFAULT 0,
  created_by UUID,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS playbook_executions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  playbook_id UUID NOT NULL,
  incident_id UUID NOT NULL,
  status TEXT NOT NULL DEFAULT 'in_progress',
  completed_steps JSONB NOT NULL DEFAULT '[]',
  started_by UUID,
  started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_playbook_exec_incident ON playbook_executions(incident_id);
