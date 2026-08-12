CREATE TABLE IF NOT EXISTS patch_deployments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  patch_type TEXT NOT NULL DEFAULT 'security',
  kb_article TEXT NOT NULL DEFAULT '',
  cve_ids JSONB NOT NULL DEFAULT '[]',
  severity TEXT NOT NULL DEFAULT 'medium',
  target_os TEXT NOT NULL DEFAULT 'all',
  target_groups JSONB NOT NULL DEFAULT '[]',
  target_agents JSONB NOT NULL DEFAULT '[]',
  status TEXT NOT NULL DEFAULT 'draft',
  scheduled_at TIMESTAMPTZ,
  deployment_window_minutes INT NOT NULL DEFAULT 60,
  require_reboot BOOL NOT NULL DEFAULT FALSE,
  created_by UUID,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_patch_deployments_status ON patch_deployments(status);

CREATE TABLE IF NOT EXISTS patch_deployment_results (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  deployment_id UUID NOT NULL REFERENCES patch_deployments(id) ON DELETE CASCADE,
  agent_id UUID NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  error_message TEXT NOT NULL DEFAULT '',
  started_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  reboot_required BOOL NOT NULL DEFAULT FALSE,
  UNIQUE(deployment_id, agent_id)
);
CREATE INDEX IF NOT EXISTS idx_patch_results_deployment ON patch_deployment_results(deployment_id);
CREATE INDEX IF NOT EXISTS idx_patch_results_agent ON patch_deployment_results(agent_id);
