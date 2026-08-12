-- Response Playbooks: automated response workflows triggered by alert conditions

CREATE TABLE playbooks (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name        TEXT NOT NULL,
    description TEXT,
    -- Trigger conditions (matched against alerts)
    conditions  JSONB NOT NULL DEFAULT '{}',
    -- Actions to execute when conditions are met (ordered array)
    actions     JSONB NOT NULL DEFAULT '[]',
    is_active   BOOLEAN NOT NULL DEFAULT TRUE,
    run_count   INT NOT NULL DEFAULT 0,        -- how many times triggered
    last_run_at TIMESTAMPTZ,
    created_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    updated_at  TIMESTAMPTZ DEFAULT NOW()
);

-- conditions schema (all fields optional, empty = match all):
-- { "min_severity": 7, "max_severity": 10, "rule_name": "mimikatz",
--   "hostname": "", "mitre_technique": "T1003", "status": "open" }

-- actions schema (array of action objects):
-- [
--   { "type": "isolate_endpoint" },
--   { "type": "create_incident",  "title": "Auto: {{alert.title}}", "severity": "{{alert.severity}}" },
--   { "type": "notify",           "message": "Critical alert: {{alert.title}}" },
--   { "type": "assign_alert",     "user_id": "<uuid>" }
-- ]

CREATE INDEX idx_playbooks_active ON playbooks(is_active);
CREATE INDEX idx_playbooks_created ON playbooks(created_at DESC);

-- Execution log
CREATE TABLE playbook_runs (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    playbook_id UUID REFERENCES playbooks(id) ON DELETE CASCADE,
    alert_id    TEXT NOT NULL,
    actions_run JSONB NOT NULL DEFAULT '[]',  -- list of actions that were executed
    success     BOOLEAN NOT NULL DEFAULT TRUE,
    error_msg   TEXT,
    ran_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_playbook_runs_playbook ON playbook_runs(playbook_id, ran_at DESC);
CREATE INDEX idx_playbook_runs_alert    ON playbook_runs(alert_id);
