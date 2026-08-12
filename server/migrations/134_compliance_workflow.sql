CREATE TABLE IF NOT EXISTS compliance_workflows (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name           VARCHAR(255) NOT NULL,
  framework      VARCHAR(100) NOT NULL,
  workflow_type  VARCHAR(100) NOT NULL,  -- assessment, remediation, audit, review, approval
  status         VARCHAR(50) NOT NULL DEFAULT 'active',
  stages         JSONB NOT NULL DEFAULT '[]',  -- ordered list of {name, type, assignee, due_days, actions}
  trigger_type   VARCHAR(100) NOT NULL DEFAULT 'manual',  -- manual, scheduled, event
  schedule       VARCHAR(100),
  is_active      BOOLEAN NOT NULL DEFAULT true,
  run_count      INT NOT NULL DEFAULT 0,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS compliance_workflow_runs (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workflow_id    UUID NOT NULL REFERENCES compliance_workflows(id) ON DELETE CASCADE,
  current_stage  INT NOT NULL DEFAULT 0,
  status         VARCHAR(50) NOT NULL DEFAULT 'in_progress',  -- in_progress, completed, failed, cancelled
  assignees      JSONB NOT NULL DEFAULT '{}',
  stage_results  JSONB NOT NULL DEFAULT '[]',
  due_date       TIMESTAMPTZ,
  completed_at   TIMESTAMPTZ,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_workflow_runs_workflow ON compliance_workflow_runs(workflow_id, created_at DESC);
