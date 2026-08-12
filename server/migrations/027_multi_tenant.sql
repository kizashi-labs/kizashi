-- Multi-tenant support
CREATE TABLE IF NOT EXISTS tenants (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL UNIQUE,
    slug        TEXT NOT NULL UNIQUE,
    plan        TEXT NOT NULL DEFAULT 'standard',  -- free | standard | enterprise
    max_agents  INT  NOT NULL DEFAULT 100,
    is_active   BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Add tenant_id to core tables
ALTER TABLE users ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id);
ALTER TABLE agents ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id);
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id);
ALTER TABLE rules ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id);
ALTER TABLE suppression_rules ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id);
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id);

-- Default tenant for existing data
INSERT INTO tenants (id, name, slug, plan) VALUES
('00000000-0000-0000-0000-000000000001', 'Default', 'default', 'enterprise')
ON CONFLICT (slug) DO NOTHING;

-- Migrate existing rows to default tenant
UPDATE users SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
UPDATE agents SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
UPDATE alerts SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
UPDATE rules SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
UPDATE suppression_rules SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
UPDATE incidents SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;

-- Row-level security
ALTER TABLE agents ENABLE ROW LEVEL SECURITY;
ALTER TABLE alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE incidents ENABLE ROW LEVEL SECURITY;

-- Policies: app user (edr) sees only rows matching current_setting('app.tenant_id')
-- Superuser bypasses RLS for migrations
CREATE POLICY agents_tenant_isolation ON agents
    USING (tenant_id::text = current_setting('app.tenant_id', TRUE)
           OR current_setting('app.tenant_id', TRUE) IS NULL
           OR current_setting('app.tenant_id', TRUE) = '');

CREATE POLICY alerts_tenant_isolation ON alerts
    USING (tenant_id::text = current_setting('app.tenant_id', TRUE)
           OR current_setting('app.tenant_id', TRUE) IS NULL
           OR current_setting('app.tenant_id', TRUE) = '');

CREATE POLICY incidents_tenant_isolation ON incidents
    USING (tenant_id::text = current_setting('app.tenant_id', TRUE)
           OR current_setting('app.tenant_id', TRUE) IS NULL
           OR current_setting('app.tenant_id', TRUE) = '');

-- Indexes for tenant lookups
CREATE INDEX IF NOT EXISTS users_tenant_idx ON users(tenant_id);
CREATE INDEX IF NOT EXISTS agents_tenant_idx ON agents(tenant_id);
CREATE INDEX IF NOT EXISTS alerts_tenant_idx ON alerts(tenant_id);
