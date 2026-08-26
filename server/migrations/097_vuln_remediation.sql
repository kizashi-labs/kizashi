CREATE TABLE IF NOT EXISTS vuln_remediations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  vuln_id UUID NOT NULL,
  agent_id UUID NOT NULL,
  cve_id TEXT NOT NULL,
  title TEXT NOT NULL,
  severity TEXT NOT NULL DEFAULT 'medium',
  status TEXT NOT NULL DEFAULT 'open',
  assignee_id UUID,
  due_date DATE,
  resolution_notes TEXT NOT NULL DEFAULT '',
  patch_version TEXT NOT NULL DEFAULT '',
  verified_at TIMESTAMPTZ,
  verified_by UUID,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_vuln_remediations_status ON vuln_remediations(status);
CREATE INDEX IF NOT EXISTS idx_vuln_remediations_agent ON vuln_remediations(agent_id);
CREATE INDEX IF NOT EXISTS idx_vuln_remediations_assignee ON vuln_remediations(assignee_id);
CREATE INDEX IF NOT EXISTS idx_vuln_remediations_due ON vuln_remediations(due_date);
