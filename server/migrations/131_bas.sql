CREATE TABLE IF NOT EXISTS bas_scenarios (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name           VARCHAR(255) NOT NULL,
  description    TEXT,
  scenario_type  VARCHAR(100) NOT NULL,  -- malware, phishing, lateral_movement, exfiltration, ransomware, c2
  mitre_tactics  JSONB NOT NULL DEFAULT '[]',
  mitre_techniques JSONB NOT NULL DEFAULT '[]',
  difficulty     VARCHAR(50) NOT NULL DEFAULT 'medium',
  estimated_duration_min INT NOT NULL DEFAULT 30,
  is_active      BOOLEAN NOT NULL DEFAULT true,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS bas_runs (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scenario_id    UUID NOT NULL REFERENCES bas_scenarios(id) ON DELETE CASCADE,
  target_scope   JSONB NOT NULL DEFAULT '[]',  -- list of target hostnames/IPs
  status         VARCHAR(50) NOT NULL DEFAULT 'pending',  -- pending, running, completed, failed, cancelled
  detection_rate NUMERIC(5,2),
  prevention_rate NUMERIC(5,2),
  steps_total    INT NOT NULL DEFAULT 0,
  steps_detected INT NOT NULL DEFAULT 0,
  steps_prevented INT NOT NULL DEFAULT 0,
  findings       JSONB NOT NULL DEFAULT '[]',
  started_at     TIMESTAMPTZ,
  completed_at   TIMESTAMPTZ,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_bas_runs_scenario ON bas_runs(scenario_id, created_at DESC);
