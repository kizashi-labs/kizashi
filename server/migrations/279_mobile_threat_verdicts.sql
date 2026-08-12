-- 279: mobile threat verdicts — on-device Mobile Threat Defense (MTD) signals.
--
-- The platform has no on-device iOS/Android threat agent yet; mobile detection so
-- far is MDM posture only (MobileComplianceScanner → 5 alerts). Roadmap #1 (MTD設計)
-- adds an Android integrity agent that POSTs an attestation/threat verdict to the
-- server (HTTP, the mobile analog of host telemetry — no proto/mTLS). This table is
-- the server-side landing zone for those verdicts; the verdict handler turns risky
-- ones into alerts (source='mobile-mtd', ATT&CK Mobile), reusing the scanner pattern.
-- Verifiable now via a synthetic POST — the on-device agent is the device-gated half.

CREATE TABLE IF NOT EXISTS mobile_threat_verdicts (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id           TEXT NOT NULL,                 -- mobile_devices.device_id (may be unenrolled)
    platform            TEXT NOT NULL DEFAULT 'android',
    rooted              BOOLEAN NOT NULL DEFAULT false, -- root/jailbreak (su, Magisk)
    bootloader_unlocked BOOLEAN NOT NULL DEFAULT false,
    emulator            BOOLEAN NOT NULL DEFAULT false, -- running in an emulator / non-physical device
    hooking_detected    BOOLEAN NOT NULL DEFAULT false, -- Frida / Xposed / runtime hooking
    debuggable          BOOLEAN NOT NULL DEFAULT false,
    selinux_enforcing   BOOLEAN NOT NULL DEFAULT true,  -- false = SELinux permissive (tamper signal)
    attestation_passed  BOOLEAN NOT NULL DEFAULT true,  -- Play Integrity / App Attest verdict OK
    integrity_verdict   TEXT,                           -- raw verdict label for context
    app_version         TEXT,
    raw                 JSONB,                          -- full posted body
    received_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_mobile_threat_verdicts_device
    ON mobile_threat_verdicts (device_id, received_at DESC);
