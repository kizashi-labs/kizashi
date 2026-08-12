-- レポートジョブのDB永続化（サーバー再起動後も履歴を保持）
CREATE TABLE IF NOT EXISTS report_jobs (
    id           TEXT PRIMARY KEY,
    type         TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending', -- pending|running|completed|failed
    requested_by TEXT,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    from_time    TIMESTAMPTZ,
    to_time      TIMESTAMPTZ,
    error        TEXT,
    content      JSONB
);

CREATE INDEX IF NOT EXISTS report_jobs_requested_at_idx ON report_jobs(requested_at DESC);
CREATE INDEX IF NOT EXISTS report_jobs_status_idx ON report_jobs(status);
