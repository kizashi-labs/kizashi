-- Scheduled reports: run report generation on a recurring schedule

CREATE TABLE IF NOT EXISTS report_schedules (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name         TEXT NOT NULL,
    report_type  TEXT NOT NULL,   -- 'alert_summary' | 'agent_status' | 'threat_report'
    frequency    TEXT NOT NULL CHECK (frequency IN ('daily','weekly','monthly')),
    day_of_week  INT,             -- 0=Sun..6=Sat  (for weekly)
    day_of_month INT,             -- 1-31          (for monthly)
    hour         INT NOT NULL DEFAULT 8,  -- UTC hour to run (0-23)
    recipients   TEXT[] NOT NULL DEFAULT '{}',  -- email addresses
    is_active    BOOLEAN NOT NULL DEFAULT TRUE,
    last_run_at  TIMESTAMPTZ,
    next_run_at  TIMESTAMPTZ NOT NULL,
    created_by   UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at   TIMESTAMPTZ DEFAULT NOW(),
    updated_at   TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_report_schedules_active ON report_schedules(is_active, next_run_at);
