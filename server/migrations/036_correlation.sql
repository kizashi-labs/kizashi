CREATE TABLE IF NOT EXISTS correlation_groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id TEXT NOT NULL,
    mitre_technique TEXT NOT NULL,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    alert_count INT NOT NULL DEFAULT 1,
    incident_id UUID REFERENCES incidents(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_correlation_groups_agent_technique
    ON correlation_groups(agent_id, mitre_technique, last_seen_at);
