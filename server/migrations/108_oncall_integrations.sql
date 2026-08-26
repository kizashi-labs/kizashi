CREATE TABLE IF NOT EXISTS oncall_integrations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  provider TEXT NOT NULL DEFAULT 'pagerduty',
  integration_key TEXT NOT NULL,
  api_url TEXT NOT NULL DEFAULT '',
  severity_threshold INT NOT NULL DEFAULT 8,
  enabled BOOL NOT NULL DEFAULT TRUE,
  events_sent INT NOT NULL DEFAULT 0,
  last_event_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS oncall_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  integration_id UUID NOT NULL,
  alert_id UUID,
  event_type TEXT NOT NULL DEFAULT 'trigger',
  dedup_key TEXT NOT NULL,
  summary TEXT NOT NULL,
  severity TEXT NOT NULL DEFAULT 'critical',
  status TEXT NOT NULL DEFAULT 'sent',
  response_code INT,
  sent_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_oncall_events_integration ON oncall_events(integration_id, sent_at DESC);
