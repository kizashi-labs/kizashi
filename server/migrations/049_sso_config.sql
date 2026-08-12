-- Migration 049: SSO / SAML 2.0 configuration storage
-- Stores Identity Provider (IdP) configuration for SAML and OIDC providers.
-- Production deployment requires github.com/crewjam/saml for real XML signature verification.

CREATE TABLE IF NOT EXISTS sso_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider TEXT NOT NULL CHECK (provider IN ('saml', 'oidc')),
    name TEXT NOT NULL,  -- e.g. "Okta", "Azure AD"
    -- SAML fields
    idp_entity_id TEXT,
    idp_sso_url TEXT,
    idp_certificate TEXT,  -- PEM certificate
    sp_entity_id TEXT,
    -- OIDC fields
    client_id TEXT,
    client_secret TEXT,
    discovery_url TEXT,
    -- Common
    enabled BOOL NOT NULL DEFAULT false,
    attribute_mapping JSONB DEFAULT '{"email": "email", "name": "name", "role": "role"}',
    default_role TEXT NOT NULL DEFAULT 'analyst',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
