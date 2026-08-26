-- 144: Patch Automation
CREATE TABLE IF NOT EXISTS patch_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    scope JSONB DEFAULT '{}',
    patch_categories TEXT[] DEFAULT '{}',
    severity_filter TEXT[] DEFAULT '{"critical","high"}',
    auto_approve_severity TEXT[] DEFAULT '{"critical"}',
    maintenance_window JSONB DEFAULT '{}',
    pre_patch_snapshot BOOLEAN DEFAULT true,
    rollback_enabled BOOLEAN DEFAULT true,
    test_group_size INTEGER DEFAULT 5,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS patch_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id UUID REFERENCES patch_policies(id) ON DELETE SET NULL,
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    patch_ids TEXT[] DEFAULT '{}',
    target_endpoints TEXT[] DEFAULT '{}',
    status VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','running','completed','failed','rolled_back')),
    total_endpoints INTEGER DEFAULT 0,
    patched_count INTEGER DEFAULT 0,
    failed_count INTEGER DEFAULT 0,
    pending_reboot INTEGER DEFAULT 0,
    scheduled_at TIMESTAMPTZ,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_patch_policies_tenant ON patch_policies(tenant_id);
CREATE INDEX IF NOT EXISTS idx_patch_jobs_status ON patch_jobs(status);
CREATE INDEX IF NOT EXISTS idx_patch_jobs_tenant ON patch_jobs(tenant_id);
