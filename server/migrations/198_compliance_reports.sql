CREATE TABLE IF NOT EXISTS compliance_reports (
    id           UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id     UUID         NOT NULL,
    framework    VARCHAR(32)  NOT NULL,
    score        NUMERIC(5,2) NOT NULL DEFAULT 0,
    passed       INT          NOT NULL DEFAULT 0,
    failed       INT          NOT NULL DEFAULT 0,
    unknown      INT          NOT NULL DEFAULT 0,
    details      JSONB        NOT NULL DEFAULT '[]',
    evaluated_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS compliance_reports_agent_framework_time_idx
    ON compliance_reports (agent_id, framework, evaluated_at DESC);

CREATE INDEX IF NOT EXISTS compliance_reports_framework_time_idx
    ON compliance_reports (framework, evaluated_at DESC);
