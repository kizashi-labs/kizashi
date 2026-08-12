CREATE TABLE IF NOT EXISTS saved_hunts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    params JSONB NOT NULL DEFAULT '{}',
    created_by TEXT NOT NULL DEFAULT 'system',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_run TIMESTAMPTZ,
    run_count INT NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_saved_hunts_user ON saved_hunts(created_by);
