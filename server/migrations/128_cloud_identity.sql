CREATE TABLE IF NOT EXISTS cloud_identity_providers (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name           VARCHAR(255) NOT NULL,
  provider_type  VARCHAR(100) NOT NULL,  -- azure_ad, aws_iam, google_workspace, okta, ping_identity
  tenant_id      VARCHAR(500),
  config         JSONB NOT NULL DEFAULT '{}',
  is_active      BOOLEAN NOT NULL DEFAULT true,
  sync_status    VARCHAR(50) NOT NULL DEFAULT 'pending',
  last_sync      TIMESTAMPTZ,
  user_count     INT NOT NULL DEFAULT 0,
  group_count    INT NOT NULL DEFAULT 0,
  error_msg      TEXT,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS federated_identities (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  provider_id    UUID NOT NULL REFERENCES cloud_identity_providers(id) ON DELETE CASCADE,
  external_id    VARCHAR(500) NOT NULL,
  email          VARCHAR(255) NOT NULL,
  display_name   VARCHAR(255),
  groups         JSONB NOT NULL DEFAULT '[]',
  roles          JSONB NOT NULL DEFAULT '[]',
  local_user_id  UUID,
  is_active      BOOLEAN NOT NULL DEFAULT true,
  last_seen      TIMESTAMPTZ,
  risk_indicators JSONB NOT NULL DEFAULT '[]',
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_federated_email ON federated_identities(email);
CREATE INDEX IF NOT EXISTS idx_federated_provider ON federated_identities(provider_id);
