-- 232: MDM enrollment tokens (iOS .mobileconfig / Android QR)
--
-- Flow:
--   1. Admin calls POST /api/v1/admin/mdm/enrollment-tokens → row inserted here.
--   2. Returned `token` is baked into a URL (.mobileconfig for iOS) or a QR
--      payload (Android Enterprise enrollment token).
--   3. Device fetches the URL — handler consumes the row (sets used_at) and
--      binds the resulting mobile_device to created_for_email.
--   4. Unused tokens older than expires_at are ignored.

CREATE TABLE IF NOT EXISTS mdm_enrollment_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    -- The opaque token the device presents (URL-safe base64, 32+ bytes).
    token TEXT NOT NULL UNIQUE,

    platform TEXT NOT NULL CHECK (platform IN ('ios','android')),

    -- Optional pre-binding: when set, the enrolled device's owner_email
    -- defaults to this address.
    created_for_email TEXT,

    -- For iOS: the MDM server URL that ends up in the .mobileconfig.
    -- For Android: the AE enrollmentToken.value returned by Google.
    payload JSONB NOT NULL DEFAULT '{}',

    -- Who minted it + when.
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Token consumption / expiry.
    expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '7 days',
    used_at TIMESTAMPTZ,
    used_by_device UUID REFERENCES mobile_devices(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_mdm_enrollment_tokens_platform
    ON mdm_enrollment_tokens(platform);
CREATE INDEX IF NOT EXISTS idx_mdm_enrollment_tokens_created_at
    ON mdm_enrollment_tokens(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_mdm_enrollment_tokens_unused
    ON mdm_enrollment_tokens(expires_at)
    WHERE used_at IS NULL;

-- A push_token column on mobile_devices so we can send APNs/FCM pushes.
-- The APNs device token and FCM registration token live in the same
-- column but are discriminated by the platform of the parent device.
ALTER TABLE mobile_devices
  ADD COLUMN IF NOT EXISTS push_token TEXT,
  ADD COLUMN IF NOT EXISTS push_magic TEXT,      -- Apple PushMagic (rotates per TokenUpdate)
  ADD COLUMN IF NOT EXISTS unlock_token BYTEA;   -- Apple UnlockToken for passcode-clear
