-- Capacity Planning: ROI inputs + planning targets
-- ROI is derived from investment vs. benefit inputs so customers can edit
-- values without a code deploy and the math stays honest.

CREATE TABLE IF NOT EXISTS cp_roi_inputs (
    id                         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    category                   TEXT NOT NULL UNIQUE,
    label                      TEXT NOT NULL,
    sub_label                  TEXT NOT NULL DEFAULT '',
    annual_investment          BIGINT NOT NULL DEFAULT 0,
    breach_prevention_value    BIGINT NOT NULL DEFAULT 0,
    operational_savings        BIGINT NOT NULL DEFAULT 0,
    compliance_value           BIGINT NOT NULL DEFAULT 0,
    sort_order                 INT NOT NULL DEFAULT 0,
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Singleton row for page-level planning targets (endpoint unit cost, analyst
-- headroom). Mirrors the singleton pattern used by cp_storage_metrics.
CREATE TABLE IF NOT EXISTS cp_planning_targets (
    id                         INT PRIMARY KEY DEFAULT 1,
    cost_per_endpoint_target   BIGINT NOT NULL DEFAULT 500000,
    analyst_headroom           INT NOT NULL DEFAULT 2,
    updated_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT cp_planning_targets_singleton CHECK (id = 1)
);

-- ── Seed ──────────────────────────────────────────────────────────

INSERT INTO cp_roi_inputs
    (category, label, sub_label, annual_investment,
     breach_prevention_value, operational_savings, compliance_value, sort_order)
VALUES
    ('edr',  'EDR投資ROI',  '侵害防止コスト換算', 15000000, 51000000,       0,        0, 1),
    ('siem', 'SIEM投資ROI', '運用効率化換算',     45000000,        0, 94500000,        0, 2),
    ('soar', 'SOAR投資ROI', '対応時間削減換算',   10000000,        0, 18000000,        0, 3)
ON CONFLICT (category) DO NOTHING;

INSERT INTO cp_planning_targets (id, cost_per_endpoint_target, analyst_headroom)
VALUES (1, 500000, 2)
ON CONFLICT (id) DO NOTHING;
