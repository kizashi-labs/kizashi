-- Incident notes / timeline entries
CREATE TABLE IF NOT EXISTS incident_notes (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id UUID        NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    user_id     UUID        REFERENCES users(id) ON DELETE SET NULL,
    body        TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_incident_notes_incident_id ON incident_notes(incident_id);
CREATE INDEX IF NOT EXISTS idx_incident_notes_created_at  ON incident_notes(incident_id, created_at DESC);
