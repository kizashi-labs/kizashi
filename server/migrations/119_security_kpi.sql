CREATE TABLE IF NOT EXISTS security_kpi_definitions (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name         VARCHAR(255) NOT NULL,
  description  TEXT,
  category     VARCHAR(100) NOT NULL,  -- detection, response, prevention, compliance, risk
  unit         VARCHAR(50) NOT NULL,   -- %, count, hours, score
  target_value NUMERIC(10,2) NOT NULL,
  warning_threshold NUMERIC(10,2),
  direction    VARCHAR(10) NOT NULL DEFAULT 'higher',  -- higher=better, lower=better
  is_active    BOOLEAN NOT NULL DEFAULT true,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS security_kpi_measurements (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  kpi_id       UUID NOT NULL REFERENCES security_kpi_definitions(id) ON DELETE CASCADE,
  value        NUMERIC(10,2) NOT NULL,
  period       DATE NOT NULL,  -- first day of the measurement period
  notes        TEXT,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_kpi_measurements_kpi ON security_kpi_measurements(kpi_id, period DESC);
