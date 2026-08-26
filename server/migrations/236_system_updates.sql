-- 236_system_updates.sql
--
-- System auto-update tracking — Phase 1 (schema + REST API + admin UI only).
--
-- Phase 1 ships the data model and CRUD surface so the admin UI can render
-- update history and toggle policies. Phase 2 will add the updater container
-- that polls GitHub Releases and inserts rows here. Phase 3 will execute
-- `docker compose pull/up` after admin approval. Phase 4 (unattended
-- auto-apply) is intentionally skipped — every transition stays manual.
--
-- Design ref: docs/design/system-updates-phase1.md
-- Parent ref: docs/design/auto-update-system.md

CREATE TABLE IF NOT EXISTS system_updates (
    id                    UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    current_version       TEXT        NOT NULL,
    available_version     TEXT        NOT NULL,
    release_notes_url     TEXT        NOT NULL DEFAULT '',
    release_notes_md      TEXT        NOT NULL DEFAULT '',
    channel               TEXT        NOT NULL DEFAULT 'stable'
        CHECK (channel IN ('stable', 'beta')),
    detected_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status                TEXT        NOT NULL DEFAULT 'available'
        CHECK (status IN ('available', 'approved', 'applying', 'success', 'failed', 'rolled_back', 'cancelled')),
    approved_by           UUID        REFERENCES users(id) ON DELETE SET NULL,
    approved_at           TIMESTAMPTZ,
    applied_at            TIMESTAMPTZ,
    failed_reason         TEXT        NOT NULL DEFAULT '',
    rollback_from_version TEXT        NOT NULL DEFAULT '',
    UNIQUE(available_version)
);

CREATE INDEX IF NOT EXISTS idx_system_updates_status      ON system_updates(status);
CREATE INDEX IF NOT EXISTS idx_system_updates_detected_at ON system_updates(detected_at DESC);

-- Single-row settings table (id = 1 enforced by CHECK).
CREATE TABLE IF NOT EXISTS system_update_settings (
    id                       INT         PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    auto_apply_patch         BOOL        NOT NULL DEFAULT FALSE,
    auto_apply_minor         BOOL        NOT NULL DEFAULT FALSE,
    maintenance_window_start TIME,
    maintenance_window_end   TIME,
    notify_email             TEXT        NOT NULL DEFAULT '',
    channel                  TEXT        NOT NULL DEFAULT 'stable'
        CHECK (channel IN ('stable', 'beta')),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO system_update_settings (id) VALUES (1) ON CONFLICT DO NOTHING;
