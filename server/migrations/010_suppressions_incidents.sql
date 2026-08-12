-- Suppression rules: automatically suppress alerts matching conditions

CREATE TABLE suppression_rules (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name        TEXT NOT NULL,
    description TEXT,
    conditions  JSONB NOT NULL DEFAULT '{}',  -- {rule_name, hostname, severity_max, mitre_technique, ...}
    duration_h  INT NOT NULL DEFAULT 24,       -- suppress duration in hours (0 = permanent)
    is_active   BOOLEAN DEFAULT TRUE,
    created_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    expires_at  TIMESTAMPTZ,                   -- NULL = no expiry
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    updated_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_sup_active ON suppression_rules(is_active);

-- Incidents: group related alerts into tracked incidents

CREATE TABLE incidents (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    title       TEXT NOT NULL,
    description TEXT,
    severity    INT NOT NULL DEFAULT 7 CHECK (severity BETWEEN 1 AND 10),
    status      TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'investigating', 'contained', 'resolved', 'closed')),
    assigned_to UUID REFERENCES users(id) ON DELETE SET NULL,
    created_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    updated_at  TIMESTAMPTZ DEFAULT NOW(),
    resolved_at TIMESTAMPTZ
);

CREATE INDEX idx_incidents_status   ON incidents(status);
CREATE INDEX idx_incidents_severity ON incidents(severity);
CREATE INDEX idx_incidents_created  ON incidents(created_at DESC);

-- Link alerts to incidents (many-to-many)
CREATE TABLE incident_alerts (
    incident_id UUID REFERENCES incidents(id) ON DELETE CASCADE,
    alert_id    TEXT NOT NULL,  -- UUID stored as text to match alerts.id type
    linked_at   TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (incident_id, alert_id)
);

CREATE INDEX idx_incident_alerts_alert ON incident_alerts(alert_id);
