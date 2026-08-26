-- Migration 037: Risk score auto-action rules
-- Allows configuring automatic isolation when an agent's risk score exceeds a threshold.

CREATE TABLE IF NOT EXISTS risk_action_rules (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name       TEXT NOT NULL,
    threshold  INT  NOT NULL DEFAULT 80 CHECK (threshold BETWEEN 1 AND 100),
    action     TEXT NOT NULL DEFAULT 'isolate' CHECK (action IN ('isolate', 'alert_only')),
    enabled    BOOL NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO risk_action_rules (name, threshold, action, enabled)
VALUES ('デフォルト自動隔離ルール', 80, 'isolate', false)
ON CONFLICT DO NOTHING;
