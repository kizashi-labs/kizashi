CREATE TABLE IF NOT EXISTS k8s_security_policies (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name           VARCHAR(255) NOT NULL,
  namespace      VARCHAR(255) NOT NULL DEFAULT '*',
  policy_type    VARCHAR(100) NOT NULL,  -- pod_security, network_policy, rbac, admission
  rules          JSONB NOT NULL DEFAULT '{}',
  enforcement    VARCHAR(50) NOT NULL DEFAULT 'audit',  -- audit, enforce, disabled
  violation_count INT NOT NULL DEFAULT 0,
  is_active      BOOLEAN NOT NULL DEFAULT true,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS k8s_policy_violations (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  policy_id      UUID NOT NULL REFERENCES k8s_security_policies(id) ON DELETE CASCADE,
  namespace      VARCHAR(255) NOT NULL,
  resource_type  VARCHAR(100) NOT NULL,  -- Pod, Deployment, ServiceAccount, etc.
  resource_name  VARCHAR(500) NOT NULL,
  violation_msg  TEXT NOT NULL,
  severity       VARCHAR(50) NOT NULL DEFAULT 'medium',
  status         VARCHAR(50) NOT NULL DEFAULT 'open',
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_k8s_violations_policy ON k8s_policy_violations(policy_id, created_at DESC);
