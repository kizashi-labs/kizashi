-- 282: mobile network posture/events — MTD roadmap #3 (network monitoring).
--
-- An on-device agent (Android VPNService / iOS NEPacketTunnel) or MDM profile
-- inspection reports a device's network posture: user-installed CA certs (the
-- classic MitM enabler), an HTTP proxy, cleartext connections, and destinations it
-- flagged as known-bad. The network ingest turns these into alerts (source=
-- 'mobile-mtd', ATT&CK Mobile T1410 traffic capture/redirection, T1439 insecure
-- communication). Server side is verifiable now via synthetic POST; the on-device
-- capture is the device-gated half. On iOS the actionable signal is a rogue CA /
-- proxy surfaced through the MDM configuration-profile list.

CREATE TABLE IF NOT EXISTS mobile_network_events (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id        TEXT NOT NULL,
    platform         TEXT NOT NULL DEFAULT 'android',
    user_added_ca    BOOLEAN NOT NULL DEFAULT false, -- user/enterprise-installed CA (MitM)
    proxy_configured BOOLEAN NOT NULL DEFAULT false,
    proxy_host       TEXT,
    vpn_active       BOOLEAN NOT NULL DEFAULT false,  -- posture only (not alerted alone)
    insecure_count   INT NOT NULL DEFAULT 0,          -- cleartext connections in this report
    malicious_count  INT NOT NULL DEFAULT 0,          -- known-bad destinations in this report
    raw              JSONB,                           -- full report (CA subjects, connection list)
    received_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_mobile_network_events_device
    ON mobile_network_events (device_id, received_at DESC);
