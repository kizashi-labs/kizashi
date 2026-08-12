CREATE TABLE IF NOT EXISTS pam_access_requests (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  requester_id UUID NOT NULL,
  target_resource TEXT NOT NULL,
  resource_type TEXT NOT NULL DEFAULT 'server',
  justification TEXT NOT NULL,
  access_level TEXT NOT NULL DEFAULT 'read',
  duration_minutes INT NOT NULL DEFAULT 60,
  status TEXT NOT NULL DEFAULT 'pending',
  approved_by UUID,
  approved_at TIMESTAMPTZ,
  expires_at TIMESTAMPTZ,
  denied_reason TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_pam_requests_status ON pam_access_requests(status);
CREATE INDEX IF NOT EXISTS idx_pam_requests_requester ON pam_access_requests(requester_id);

CREATE TABLE IF NOT EXISTS pam_sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  request_id UUID NOT NULL REFERENCES pam_access_requests(id),
  session_token TEXT NOT NULL UNIQUE,
  started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  ended_at TIMESTAMPTZ,
  commands_executed INT NOT NULL DEFAULT 0,
  recording_path TEXT,
  is_active BOOL NOT NULL DEFAULT TRUE
);
CREATE INDEX IF NOT EXISTS idx_pam_sessions_request ON pam_sessions(request_id);
CREATE INDEX IF NOT EXISTS idx_pam_sessions_active ON pam_sessions(is_active);
