CREATE TABLE IF NOT EXISTS autonomous_response_policies (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name           VARCHAR(255) NOT NULL,
  description    TEXT,
  trigger_conditions JSONB NOT NULL DEFAULT '[]',
  response_actions   JSONB NOT NULL DEFAULT '[]',  -- ordered list of {action_type, params, timeout_s}
  requires_approval  BOOLEAN NOT NULL DEFAULT false,
  approval_timeout_s INT NOT NULL DEFAULT 300,
  max_scope       VARCHAR(100) NOT NULL DEFAULT 'single_host',  -- single_host, subnet, all
  is_active       BOOLEAN NOT NULL DEFAULT true,
  execution_count INT NOT NULL DEFAULT 0,
  success_count   INT NOT NULL DEFAULT 0,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS autonomous_response_executions (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  policy_id      UUID NOT NULL REFERENCES autonomous_response_policies(id) ON DELETE CASCADE,
  trigger_event  JSONB NOT NULL DEFAULT '{}',
  status         VARCHAR(50) NOT NULL DEFAULT 'pending',  -- pending, awaiting_approval, approved, running, completed, failed, rejected
  actions_taken  JSONB NOT NULL DEFAULT '[]',
  affected_hosts JSONB NOT NULL DEFAULT '[]',
  approved_by    UUID,
  approved_at    TIMESTAMPTZ,
  started_at     TIMESTAMPTZ,
  completed_at   TIMESTAMPTZ,
  error_msg      TEXT,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_ar_executions_policy ON autonomous_response_executions(policy_id, created_at DESC);
