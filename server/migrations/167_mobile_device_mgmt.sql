-- 167: mobile device management (MDM)
CREATE TABLE IF NOT EXISTS mobile_devices (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    device_id TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    platform TEXT NOT NULL DEFAULT 'ios' CHECK (platform IN ('ios','android','windows_mobile','other')),
    os_version TEXT,
    model TEXT,
    owner_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    owner_email TEXT,
    department TEXT,
    enrolled_at TIMESTAMPTZ,
    last_seen TIMESTAMPTZ,
    compliance_status TEXT NOT NULL DEFAULT 'unknown' CHECK (compliance_status IN ('compliant','non_compliant','unknown','pending')),
    encryption_enabled BOOLEAN DEFAULT false,
    screen_lock_enabled BOOLEAN DEFAULT false,
    jailbroken BOOLEAN DEFAULT false,
    managed BOOLEAN NOT NULL DEFAULT true,
    mdm_profile_installed BOOLEAN DEFAULT false,
    tags TEXT[] DEFAULT '{}',
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS mobile_device_policies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL,
    platform TEXT NOT NULL DEFAULT 'all',
    require_encryption BOOLEAN NOT NULL DEFAULT true,
    require_screen_lock BOOLEAN NOT NULL DEFAULT true,
    min_os_version TEXT,
    allow_jailbroken BOOLEAN NOT NULL DEFAULT false,
    max_days_offline INT NOT NULL DEFAULT 7,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_mobile_devices_platform ON mobile_devices(platform);
CREATE INDEX IF NOT EXISTS idx_mobile_devices_compliance ON mobile_devices(compliance_status);
CREATE INDEX IF NOT EXISTS idx_mobile_devices_owner ON mobile_devices(owner_user_id);
