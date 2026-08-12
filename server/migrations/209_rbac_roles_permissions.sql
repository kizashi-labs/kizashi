-- Migration 209: RBAC Roles and Permission Matrix
-- B-01: Custom role definitions and per-role permission grants

CREATE TABLE IF NOT EXISTS rbac_roles (
  name        TEXT PRIMARY KEY,
  description TEXT NOT NULL DEFAULT '',
  color       TEXT NOT NULL DEFAULT '',
  is_system   BOOLEAN NOT NULL DEFAULT false,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed built-in system roles
INSERT INTO rbac_roles (name, description, color, is_system) VALUES
  ('admin',    'System administrator with full access', 'text-red-400',    true),
  ('analyst',  'Security analyst with operational access', 'text-blue-400', true),
  ('viewer',   'Read-only observer', 'text-gray-400',                       true)
ON CONFLICT (name) DO NOTHING;

CREATE TABLE IF NOT EXISTS rbac_permissions (
  role_name   TEXT PRIMARY KEY REFERENCES rbac_roles(name) ON DELETE CASCADE,
  permissions JSONB NOT NULL DEFAULT '[]',
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed default permissions
INSERT INTO rbac_permissions (role_name, permissions) VALUES
  ('admin',   '["view_alerts","manage_alerts","close_alerts","assign_alerts","export_alerts","view_agents","manage_agents","deploy_agents","run_commands","view_incidents","manage_incidents","close_incidents","view_rules","manage_rules","import_rules","view_reports","generate_reports","schedule_reports","admin_settings","manage_users","view_audit"]'),
  ('analyst', '["view_alerts","manage_alerts","close_alerts","assign_alerts","export_alerts","view_agents","view_incidents","manage_incidents","view_rules","view_reports","generate_reports"]'),
  ('viewer',  '["view_alerts","view_agents","view_incidents","view_rules","view_reports"]')
ON CONFLICT (role_name) DO NOTHING;
