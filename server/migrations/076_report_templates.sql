-- Migration 076: Report Templates
-- Stores reusable report template definitions with section configurations.

CREATE TABLE IF NOT EXISTS report_templates (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT        NOT NULL,
    description TEXT        DEFAULT '',
    sections    JSONB       NOT NULL DEFAULT '[]',
    variables   JSONB       NOT NULL DEFAULT '{}',
    format      TEXT        NOT NULL DEFAULT 'pdf',
    enabled     BOOLEAN     NOT NULL DEFAULT TRUE,
    created_by  UUID,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Default built-in templates
INSERT INTO report_templates (name, description, sections, variables, format, enabled) VALUES
(
    'Weekly Security Report',
    'Comprehensive weekly security summary including alerts, agents, and threat statistics.',
    '[
        {"type":"summary","title":"Executive Summary","config":{}},
        {"type":"alert_table","title":"Alert Summary","config":{"limit":50}},
        {"type":"chart","title":"Alert Trend","config":{"days":7}},
        {"type":"agent_overview","title":"Agent Overview","config":{}},
        {"type":"threat_stats","title":"Threat Statistics","config":{}}
    ]'::jsonb,
    '{"period":"7d","include_resolved":true}'::jsonb,
    'pdf',
    true
),
(
    'Executive Summary',
    'High-level executive overview with key metrics and risk indicators.',
    '[
        {"type":"summary","title":"Executive Summary","config":{}},
        {"type":"chart","title":"Alert Trend (30 days)","config":{"days":30}},
        {"type":"threat_stats","title":"Top Threats","config":{"limit":10}}
    ]'::jsonb,
    '{"period":"30d"}'::jsonb,
    'pdf',
    true
),
(
    'Compliance Report',
    'Compliance posture report covering policy adherence and audit findings.',
    '[
        {"type":"summary","title":"Compliance Overview","config":{}},
        {"type":"compliance_status","title":"Compliance Status","config":{}},
        {"type":"alert_table","title":"Policy Violation Alerts","config":{"limit":100,"severity_min":5}},
        {"type":"agent_overview","title":"Endpoint Coverage","config":{}}
    ]'::jsonb,
    '{"period":"30d","frameworks":["CIS","NIST"]}'::jsonb,
    'pdf',
    true
);

-- Index for ordering
CREATE INDEX IF NOT EXISTS idx_report_templates_created_at ON report_templates (created_at DESC);
