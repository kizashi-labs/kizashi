CREATE TABLE IF NOT EXISTS zero_trust_policies (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  policy_type TEXT NOT NULL DEFAULT 'network',
  conditions JSONB NOT NULL DEFAULT '{}',
  action TEXT NOT NULL DEFAULT 'deny',
  priority INT NOT NULL DEFAULT 100,
  enabled BOOL NOT NULL DEFAULT TRUE,
  match_count INT NOT NULL DEFAULT 0,
  created_by UUID,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_zt_policies_enabled ON zero_trust_policies(enabled);
CREATE INDEX IF NOT EXISTS idx_zt_policies_priority ON zero_trust_policies(priority);

CREATE TABLE IF NOT EXISTS zero_trust_access_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  policy_id UUID,
  agent_id UUID,
  user_id UUID,
  resource TEXT NOT NULL,
  action TEXT NOT NULL,
  decision TEXT NOT NULL,
  reason TEXT NOT NULL DEFAULT '',
  risk_score INT NOT NULL DEFAULT 0,
  logged_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_zt_logs_time ON zero_trust_access_logs(logged_at DESC);
CREATE INDEX IF NOT EXISTS idx_zt_logs_agent ON zero_trust_access_logs(agent_id);
