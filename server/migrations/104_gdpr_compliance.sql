CREATE TABLE IF NOT EXISTS data_subjects (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  subject_type TEXT NOT NULL DEFAULT 'employee',
  email TEXT NOT NULL,
  name TEXT NOT NULL DEFAULT '',
  data_categories JSONB NOT NULL DEFAULT '[]',
  consent_given BOOL NOT NULL DEFAULT FALSE,
  consent_date TIMESTAMPTZ,
  retention_period_days INT NOT NULL DEFAULT 365,
  deletion_requested_at TIMESTAMPTZ,
  deletion_completed_at TIMESTAMPTZ,
  notes TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_data_subjects_email ON data_subjects(email);

CREATE TABLE IF NOT EXISTS privacy_incidents (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  incident_type TEXT NOT NULL DEFAULT 'breach',
  description TEXT NOT NULL,
  affected_subjects_count INT NOT NULL DEFAULT 0,
  data_categories JSONB NOT NULL DEFAULT '[]',
  severity TEXT NOT NULL DEFAULT 'medium',
  reported_to_authority BOOL NOT NULL DEFAULT FALSE,
  reported_at TIMESTAMPTZ,
  remediation_steps TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'open',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS dsar_requests (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  request_type TEXT NOT NULL DEFAULT 'access',
  subject_email TEXT NOT NULL,
  subject_name TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'pending',
  due_date DATE NOT NULL,
  completed_at TIMESTAMPTZ,
  response_notes TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_dsar_status ON dsar_requests(status);
CREATE INDEX IF NOT EXISTS idx_dsar_due ON dsar_requests(due_date);
