-- Migration 212: Automation Workflows
-- B-05: SOAR-lite workflow definitions and run history

CREATE TABLE IF NOT EXISTS automation_workflows (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name        TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  trigger     JSONB NOT NULL DEFAULT '{}',
  actions     JSONB NOT NULL DEFAULT '[]',
  status      TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('active','paused','draft')),
  run_count   INT NOT NULL DEFAULT 0,
  success_rate FLOAT NOT NULL DEFAULT 0,
  last_run    TIMESTAMPTZ,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS automation_run_history (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workflow_id  UUID NOT NULL REFERENCES automation_workflows(id) ON DELETE CASCADE,
  trigger_info TEXT NOT NULL DEFAULT '',
  started_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  duration_ms  INT NOT NULL DEFAULT 0,
  status       TEXT NOT NULL DEFAULT 'success' CHECK (status IN ('success','failure','running')),
  steps        JSONB NOT NULL DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS idx_automation_run_history_wf ON automation_run_history(workflow_id);
