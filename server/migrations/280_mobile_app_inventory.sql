-- 280: mobile app inventory — installed-app posture for MTD roadmap #2.
--
-- An on-device agent (Android) or MDM managed-app list (iOS) reports the apps a
-- device has installed, their provenance (store vs sideloaded/enterprise) and
-- granted permissions. The app-inventory ingest detects the classic mobile-malware
-- shapes — banking-trojan permission combos (notification access + accessibility),
-- SMS interception, device-admin abuse, sideloaded/non-store apps — and alerts
-- (source='mobile-mtd', ATT&CK Mobile T1418/T1517/T1626.001/T1453/T1582).
-- Server side is verifiable now via synthetic POST; the on-device collector is the
-- device-gated half. iOS surfaces fewer signals (sandbox) — chiefly sideloaded /
-- enterprise-distributed apps via MDM — which is what an iOS-only fleet can use.

CREATE TABLE IF NOT EXISTS mobile_app_inventory (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id        TEXT NOT NULL,                 -- mobile_devices.device_id
    platform         TEXT NOT NULL DEFAULT 'android',
    package          TEXT NOT NULL,                 -- Android package / iOS bundle id
    app_name         TEXT,
    version          TEXT,
    installer_source TEXT,                          -- play_store / app_store / sideloaded / enterprise / unknown
    signer           TEXT,                          -- signing cert / team id
    permissions      TEXT[] NOT NULL DEFAULT '{}',
    is_system        BOOLEAN NOT NULL DEFAULT false,
    first_seen       TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen        TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (device_id, package)
);

CREATE INDEX IF NOT EXISTS idx_mobile_app_inventory_device
    ON mobile_app_inventory (device_id);
