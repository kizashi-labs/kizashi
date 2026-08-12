-- 157: security SLA policies and tracking
CREATE TABLE IF NOT EXISTS sla_policies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('critical','high','medium','low','info')),
    response_minutes INT NOT NULL DEFAULT 60,
    resolution_hours INT NOT NULL DEFAULT 24,
    escalation_hours INT NOT NULL DEFAULT 8,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS sla_tracking (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    alert_id UUID REFERENCES alerts(id) ON DELETE CASCADE,
    policy_id UUID REFERENCES sla_policies(id) ON DELETE SET NULL,
    response_deadline TIMESTAMPTZ,
    resolution_deadline TIMESTAMPTZ,
    responded_at TIMESTAMPTZ,
    resolved_at TIMESTAMPTZ,
    response_breached BOOLEAN NOT NULL DEFAULT false,
    resolution_breached BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_sla_tracking_alert ON sla_tracking(alert_id);
CREATE INDEX IF NOT EXISTS idx_sla_tracking_breached ON sla_tracking(response_breached, resolution_breached);
