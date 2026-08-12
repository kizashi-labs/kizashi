-- 064_saved_hunt_queries.sql
CREATE TABLE IF NOT EXISTS saved_hunt_queries (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL,
    description TEXT,
    query       TEXT NOT NULL,
    query_type  TEXT NOT NULL DEFAULT 'sql' CHECK (query_type IN ('sql','kql','yara','sigma')),
    tags        TEXT[] NOT NULL DEFAULT '{}',
    created_by  UUID,
    is_shared   BOOLEAN NOT NULL DEFAULT false,
    run_count   INTEGER NOT NULL DEFAULT 0,
    last_run_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_saved_hunt_queries_created_by ON saved_hunt_queries(created_by);
CREATE INDEX IF NOT EXISTS idx_saved_hunt_queries_shared ON saved_hunt_queries(is_shared) WHERE is_shared = true;
