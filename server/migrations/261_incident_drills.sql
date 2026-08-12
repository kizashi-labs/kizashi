-- 261: Incident response drills — tabletop / technical exercises with scoring.
-- Backs the /admin/incident-drills page: schedule a drill, run it, then record
-- the resulting scorecard (overall score + per-category breakdown + findings).

CREATE TABLE IF NOT EXISTS incident_drills (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id             UUID NOT NULL,
    name                  TEXT NOT NULL,
    drill_type            TEXT NOT NULL DEFAULT 'tabletop'
                              CHECK (drill_type IN ('tabletop','technical','communication','full_scale')),
    scenario              TEXT NOT NULL DEFAULT '',
    scenario_template     TEXT NOT NULL DEFAULT 'custom',
    status                TEXT NOT NULL DEFAULT 'scheduled'
                              CHECK (status IN ('draft','scheduled','in_progress','completed')),
    scheduled_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    participants          JSONB NOT NULL DEFAULT '[]',
    facilitator           TEXT NOT NULL DEFAULT '',
    objectives            JSONB NOT NULL DEFAULT '[]',
    is_timed              BOOLEAN NOT NULL DEFAULT TRUE,
    duration_minutes      INTEGER NOT NULL DEFAULT 60,
    -- Populated when the drill completes.
    overall_score         INTEGER,
    key_findings          TEXT,
    best_performer        TEXT,
    areas_for_improvement JSONB,
    score_breakdown       JSONB,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_incident_drills_tenant_status
    ON incident_drills(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_incident_drills_scheduled
    ON incident_drills(scheduled_at DESC);
