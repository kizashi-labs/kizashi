CREATE TABLE IF NOT EXISTS soc_tickets (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  ticket_number TEXT NOT NULL UNIQUE,
  alert_id UUID,
  incident_id UUID,
  title TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'open',
  priority TEXT NOT NULL DEFAULT 'medium',
  assignee_id UUID,
  tags JSONB NOT NULL DEFAULT '[]',
  external_id TEXT,
  external_system TEXT,
  sla_due_at TIMESTAMPTZ,
  resolved_at TIMESTAMPTZ,
  created_by UUID,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_soc_tickets_status ON soc_tickets(status);
CREATE INDEX IF NOT EXISTS idx_soc_tickets_alert ON soc_tickets(alert_id);
CREATE INDEX IF NOT EXISTS idx_soc_tickets_assignee ON soc_tickets(assignee_id);

CREATE TABLE IF NOT EXISTS soc_ticket_comments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  ticket_id UUID NOT NULL REFERENCES soc_tickets(id) ON DELETE CASCADE,
  content TEXT NOT NULL,
  author_id UUID,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
