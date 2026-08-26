-- 231: Full MDM (profiles, commands, apps, integrations)

-- Extend mobile_devices with MDM-specific identifiers
ALTER TABLE mobile_devices
  ADD COLUMN IF NOT EXISTS serial_number TEXT,
  ADD COLUMN IF NOT EXISTS udid TEXT,
  ADD COLUMN IF NOT EXISTS imei TEXT,
  ADD COLUMN IF NOT EXISTS supervised BOOLEAN DEFAULT false,
  ADD COLUMN IF NOT EXISTS enrollment_method TEXT DEFAULT 'manual'
    CHECK (enrollment_method IN ('manual','qr','dep','ae_zero_touch','knox_mobile')),
  ADD COLUMN IF NOT EXISTS mdm_server_url TEXT,
  ADD COLUMN IF NOT EXISTS enrollment_profile_id UUID;

CREATE UNIQUE INDEX IF NOT EXISTS ux_mobile_devices_serial ON mobile_devices(serial_number) WHERE serial_number IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS ux_mobile_devices_udid ON mobile_devices(udid) WHERE udid IS NOT NULL;

-- ── MDM Configuration Profiles ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS mdm_profiles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL,
    description TEXT,
    platform TEXT NOT NULL CHECK (platform IN ('ios','android','windows_mobile','all')),
    profile_type TEXT NOT NULL CHECK (profile_type IN (
      'passcode','wifi','vpn','email','restrictions','certificate',
      'app_config','single_app','web_clip','custom'
    )),
    payload JSONB NOT NULL DEFAULT '{}',
    version INT NOT NULL DEFAULT 1,
    signed BOOLEAN NOT NULL DEFAULT false,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_mdm_profiles_platform ON mdm_profiles(platform);
CREATE INDEX IF NOT EXISTS idx_mdm_profiles_type ON mdm_profiles(profile_type);

CREATE TABLE IF NOT EXISTS mdm_profile_assignments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    profile_id UUID NOT NULL REFERENCES mdm_profiles(id) ON DELETE CASCADE,
    device_id UUID REFERENCES mobile_devices(id) ON DELETE CASCADE,
    group_filter JSONB DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'pending'
      CHECK (status IN ('pending','installed','failed','removed')),
    installed_at TIMESTAMPTZ,
    failure_reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_mdm_assign_device ON mdm_profile_assignments(device_id);
CREATE INDEX IF NOT EXISTS idx_mdm_assign_profile ON mdm_profile_assignments(profile_id);

-- ── MDM Commands (queue + history) ────────────────────────────────────────
CREATE TABLE IF NOT EXISTS mdm_commands (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    device_id UUID NOT NULL REFERENCES mobile_devices(id) ON DELETE CASCADE,
    command_type TEXT NOT NULL CHECK (command_type IN (
      'device_lock','erase_device','clear_passcode','restart_device','shutdown',
      'install_profile','remove_profile','install_app','remove_app',
      'refresh_inventory','enable_lost_mode','disable_lost_mode','play_sound'
    )),
    payload JSONB DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'queued'
      CHECK (status IN ('queued','sent','acknowledged','failed','expired')),
    result JSONB,
    requested_by UUID REFERENCES users(id) ON DELETE SET NULL,
    queued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    sent_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_mdm_commands_device ON mdm_commands(device_id, status);
CREATE INDEX IF NOT EXISTS idx_mdm_commands_queued ON mdm_commands(queued_at DESC);

-- ── Managed Apps (VPP / Managed Play) ─────────────────────────────────────
CREATE TABLE IF NOT EXISTS mdm_apps (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL,
    platform TEXT NOT NULL CHECK (platform IN ('ios','android','windows_mobile')),
    bundle_id TEXT NOT NULL,
    version TEXT,
    source TEXT NOT NULL CHECK (source IN ('vpp','managed_play','enterprise','public_store')),
    vpp_token_ref TEXT,
    license_count INT DEFAULT 0,
    license_used INT DEFAULT 0,
    icon_url TEXT,
    config JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_mdm_apps_bundle ON mdm_apps(platform, bundle_id);

CREATE TABLE IF NOT EXISTS mdm_app_assignments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    app_id UUID NOT NULL REFERENCES mdm_apps(id) ON DELETE CASCADE,
    device_id UUID REFERENCES mobile_devices(id) ON DELETE CASCADE,
    install_mode TEXT NOT NULL DEFAULT 'optional'
      CHECK (install_mode IN ('required','optional','forbidden')),
    status TEXT NOT NULL DEFAULT 'pending'
      CHECK (status IN ('pending','installed','uninstalled','failed')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_mdm_app_assign_device ON mdm_app_assignments(device_id);

-- ── Integrations (ABM / Android Enterprise / SCEP) ────────────────────────
CREATE TABLE IF NOT EXISTS mdm_integrations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    integration_type TEXT NOT NULL UNIQUE
      CHECK (integration_type IN ('apple_business_manager','android_enterprise','scep','apns')),
    display_name TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT false,
    config JSONB NOT NULL DEFAULT '{}',
    credentials_encrypted BYTEA,
    last_sync_at TIMESTAMPTZ,
    last_sync_status TEXT,
    last_sync_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed integration rows so the UI always has the 4 cards
INSERT INTO mdm_integrations (integration_type, display_name, enabled, config)
VALUES
  ('apple_business_manager', 'Apple Business Manager', false, '{"server_token_uploaded": false}'),
  ('android_enterprise',     'Android Enterprise',      false, '{"enterprise_id": null}'),
  ('scep',                   'SCEP Certificate Server', false, '{"scep_url": null}'),
  ('apns',                   'APNs Push Certificate',    false, '{"topic": null, "expires_at": null}')
ON CONFLICT (integration_type) DO NOTHING;
