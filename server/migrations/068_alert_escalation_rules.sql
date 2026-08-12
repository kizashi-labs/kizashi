CREATE TABLE IF NOT EXISTS alert_escalation_rules (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL,
    severity_min    SMALLINT NOT NULL DEFAULT 5,
    unresolved_mins INT NOT NULL DEFAULT 60,
    escalate_to     TEXT NOT NULL,  -- email or user_id
    notify_channel  TEXT,           -- optional notification channel name
    enabled         BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
