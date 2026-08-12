-- 259: Data retention policies — admin-editable retention settings per data type.
-- Live record counts/sizes are computed at request time; this table stores the
-- configured policy and the last manual purge timestamp.

CREATE TABLE IF NOT EXISTS data_retention_policies (
    type           TEXT PRIMARY KEY,
    retention_days INTEGER,                        -- NULL = keep forever
    auto_purge     BOOLEAN NOT NULL DEFAULT FALSE,
    purge_schedule TEXT NOT NULL DEFAULT 'daily' CHECK (purge_schedule IN ('daily','weekly','monthly')),
    last_purge     TIMESTAMPTZ,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO data_retention_policies (type, retention_days)
SELECT v.type, v.days FROM (VALUES
    ('alerts', 90),
    ('events', 30),
    ('audit_logs', 365),
    ('playbook_runs', 180),
    ('darkweb_findings', 365)
) AS v(type, days)
WHERE NOT EXISTS (SELECT 1 FROM data_retention_policies p WHERE p.type = v.type);
