-- テナントスコープのロール管理
-- ロール: tenant_admin (テナント内全権), analyst (読み書き), viewer (読み取りのみ)

CREATE TYPE tenant_role AS ENUM ('tenant_admin', 'analyst', 'viewer');

CREATE TABLE IF NOT EXISTS tenant_roles (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role        tenant_role NOT NULL DEFAULT 'viewer',
    granted_by  UUID REFERENCES users(id),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, user_id)
);

CREATE INDEX idx_tenant_roles_tenant ON tenant_roles(tenant_id);
CREATE INDEX idx_tenant_roles_user ON tenant_roles(user_id);

-- デフォルトテナントの既存ユーザーをanalystとして移行
INSERT INTO tenant_roles (tenant_id, user_id, role)
SELECT '00000000-0000-0000-0000-000000000001'::uuid, id, 'analyst'
FROM users
WHERE tenant_id = '00000000-0000-0000-0000-000000000001'
   OR tenant_id IS NULL
ON CONFLICT DO NOTHING;
