-- Enhanced multi-tenancy: tenant quotas, isolation settings, audit log
CREATE TABLE IF NOT EXISTS tenant_quotas (
  tenant_id    UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
  max_agents   INT NOT NULL DEFAULT 100,
  max_users    INT NOT NULL DEFAULT 50,
  max_storage_gb BIGINT NOT NULL DEFAULT 100,
  max_alerts_per_day INT NOT NULL DEFAULT 10000,
  plan         VARCHAR(50) NOT NULL DEFAULT 'standard',
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS tenant_audit_log (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  actor_id     UUID,
  actor_email  VARCHAR(255),
  action       VARCHAR(100) NOT NULL,
  resource     VARCHAR(100),
  resource_id  VARCHAR(255),
  details      JSONB,
  ip_address   INET,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_tenant_audit_tenant_id ON tenant_audit_log(tenant_id, created_at DESC);
