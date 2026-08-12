-- Migration 047: USB/external device connection events
-- Stores device connect/disconnect events reported by EDR agents.

CREATE TABLE IF NOT EXISTS device_events (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id    TEXT        NOT NULL,
    action      TEXT        NOT NULL CHECK (action IN ('connected', 'disconnected')),
    device_id   TEXT        NOT NULL,
    device_name TEXT,
    device_type TEXT,
    vendor_id   TEXT,
    product_id  TEXT,
    raw_data    JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_device_events_agent
    ON device_events (agent_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_device_events_action
    ON device_events (action, created_at DESC);
