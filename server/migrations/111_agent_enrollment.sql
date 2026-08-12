CREATE TABLE IF NOT EXISTS agent_enrollment_requests (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  hostname TEXT NOT NULL,
  ip_address TEXT NOT NULL,
  os_type TEXT NOT NULL,
  os_version TEXT NOT NULL DEFAULT '',
  machine_id TEXT NOT NULL UNIQUE,
  enrollment_token TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  approved_by UUID,
  approved_at TIMESTAMPTZ,
  denied_reason TEXT,
  auto_approved BOOL NOT NULL DEFAULT FALSE,
  agent_id UUID,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_enrollment_status ON agent_enrollment_requests(status);
CREATE INDEX IF NOT EXISTS idx_enrollment_machine ON agent_enrollment_requests(machine_id);

CREATE TABLE IF NOT EXISTS enrollment_rules (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  match_field TEXT NOT NULL DEFAULT 'hostname',
  match_pattern TEXT NOT NULL,
  action TEXT NOT NULL DEFAULT 'auto_approve',
  assign_group_id UUID,
  assign_tags JSONB NOT NULL DEFAULT '[]',
  priority INT NOT NULL DEFAULT 100,
  enabled BOOL NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
