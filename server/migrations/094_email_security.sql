CREATE TABLE IF NOT EXISTS email_security_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  message_id TEXT NOT NULL,
  sender TEXT NOT NULL,
  recipients JSONB NOT NULL DEFAULT '[]',
  subject TEXT NOT NULL,
  threat_type TEXT NOT NULL DEFAULT 'none',
  verdict TEXT NOT NULL DEFAULT 'clean',
  confidence_score INT NOT NULL DEFAULT 0,
  attachments JSONB NOT NULL DEFAULT '[]',
  urls JSONB NOT NULL DEFAULT '[]',
  action_taken TEXT NOT NULL DEFAULT 'delivered',
  received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  analyzed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_email_events_verdict ON email_security_events(verdict);
CREATE INDEX IF NOT EXISTS idx_email_events_time ON email_security_events(received_at DESC);
CREATE INDEX IF NOT EXISTS idx_email_events_sender ON email_security_events(sender);
