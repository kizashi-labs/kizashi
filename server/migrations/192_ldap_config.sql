-- Migration 192: LDAP/Active Directory Configuration and User Cache

CREATE TABLE IF NOT EXISTS ldap_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host TEXT NOT NULL,
    port TEXT DEFAULT '389',
    bind_dn TEXT,
    bind_password TEXT,
    base_dn TEXT,
    use_tls BOOLEAN DEFAULT false,
    enabled BOOLEAN DEFAULT false,
    last_sync TIMESTAMPTZ,
    user_count INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ad_users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sam_account_name TEXT NOT NULL UNIQUE,
    display_name TEXT,
    email TEXT,
    department TEXT,
    groups TEXT[] DEFAULT '{}',
    last_logon TIMESTAMPTZ,
    password_last_set TIMESTAMPTZ,
    enabled BOOLEAN DEFAULT true,
    admin_count INTEGER DEFAULT 0,
    synced_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ad_users_sam ON ad_users(sam_account_name);
CREATE INDEX IF NOT EXISTS idx_ad_users_admin ON ad_users(admin_count) WHERE admin_count > 0;
