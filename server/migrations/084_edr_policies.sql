CREATE TABLE IF NOT EXISTS edr_policies (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  policy_type TEXT NOT NULL DEFAULT 'standard',
  rules JSONB NOT NULL DEFAULT '{}',
  enabled BOOL NOT NULL DEFAULT TRUE,
  assigned_groups JSONB NOT NULL DEFAULT '[]',
  created_by UUID,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_edr_policies_enabled ON edr_policies(enabled);

CREATE TABLE IF NOT EXISTS edr_policy_assignments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  policy_id UUID NOT NULL REFERENCES edr_policies(id) ON DELETE CASCADE,
  agent_id UUID,
  group_id UUID,
  assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  assigned_by UUID,
  UNIQUE(policy_id, agent_id),
  UNIQUE(policy_id, group_id)
);
