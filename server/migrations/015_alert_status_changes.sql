-- Migration 015: Alert status change tracking for accurate MTTD/MTTR
-- Records every status transition on an alert with timestamp and actor.

CREATE TABLE IF NOT EXISTS alert_status_changes (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    alert_id    UUID NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    from_status TEXT,                         -- NULL = initial status on creation
    to_status   TEXT NOT NULL,
    changed_by  TEXT NOT NULL DEFAULT 'system', -- 'system' | user_id | 'ai_agent'
    changed_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS alert_status_changes_alert_idx ON alert_status_changes(alert_id);
CREATE INDEX IF NOT EXISTS alert_status_changes_at_idx    ON alert_status_changes(changed_at DESC);

-- Backfill existing alerts with an initial 'open' status change record
INSERT INTO alert_status_changes (alert_id, from_status, to_status, changed_by, changed_at)
SELECT id, NULL, status, 'system', created_at
FROM alerts
WHERE NOT EXISTS (
    SELECT 1 FROM alert_status_changes asc2 WHERE asc2.alert_id = alerts.id
)
ON CONFLICT DO NOTHING;
