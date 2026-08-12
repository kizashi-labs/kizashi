CREATE TABLE IF NOT EXISTS report_schedules_v2 (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name           VARCHAR(255) NOT NULL,
  report_type    VARCHAR(100) NOT NULL,  -- executive, operational, compliance, threat_intel, custom
  description    TEXT,
  template_id    VARCHAR(100),
  schedule       VARCHAR(100) NOT NULL,  -- cron expression
  recipients     JSONB NOT NULL DEFAULT '[]',
  parameters     JSONB NOT NULL DEFAULT '{}',
  output_format  VARCHAR(50) NOT NULL DEFAULT 'pdf',  -- pdf, html, json, csv
  is_active      BOOLEAN NOT NULL DEFAULT true,
  last_run       TIMESTAMPTZ,
  next_run       TIMESTAMPTZ,
  run_count      INT NOT NULL DEFAULT 0,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS generated_reports (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  schedule_id    UUID REFERENCES report_schedules_v2(id) ON DELETE SET NULL,
  name           VARCHAR(255) NOT NULL,
  report_type    VARCHAR(100) NOT NULL,
  period_start   TIMESTAMPTZ,
  period_end     TIMESTAMPTZ,
  status         VARCHAR(50) NOT NULL DEFAULT 'pending',  -- pending, generating, completed, failed
  file_size_kb   INT,
  output_format  VARCHAR(50) NOT NULL DEFAULT 'pdf',
  generated_by   UUID,
  generated_at   TIMESTAMPTZ,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_generated_reports_type ON generated_reports(report_type, created_at DESC);
