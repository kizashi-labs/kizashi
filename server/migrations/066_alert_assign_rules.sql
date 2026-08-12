CREATE TABLE IF NOT EXISTS alert_assign_rules (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL,
    priority    INT NOT NULL DEFAULT 0,
    conditions  JSONB NOT NULL DEFAULT '{}',
    assignee_id UUID NOT NULL,
    enabled     BOOLEAN NOT NULL DEFAULT true,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_alert_assign_rules_enabled ON alert_assign_rules(enabled, priority DESC);
