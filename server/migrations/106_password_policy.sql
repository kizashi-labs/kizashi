CREATE TABLE IF NOT EXISTS password_policies (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL DEFAULT 'default',
  min_length INT NOT NULL DEFAULT 12,
  max_length INT NOT NULL DEFAULT 128,
  require_uppercase BOOL NOT NULL DEFAULT TRUE,
  require_lowercase BOOL NOT NULL DEFAULT TRUE,
  require_digits BOOL NOT NULL DEFAULT TRUE,
  require_special BOOL NOT NULL DEFAULT TRUE,
  min_special_chars INT NOT NULL DEFAULT 1,
  password_history_count INT NOT NULL DEFAULT 5,
  max_age_days INT NOT NULL DEFAULT 90,
  min_age_days INT NOT NULL DEFAULT 1,
  lockout_attempts INT NOT NULL DEFAULT 5,
  lockout_duration_minutes INT NOT NULL DEFAULT 30,
  is_active BOOL NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Insert default policy
INSERT INTO password_policies (name) VALUES ('default') ON CONFLICT DO NOTHING;
