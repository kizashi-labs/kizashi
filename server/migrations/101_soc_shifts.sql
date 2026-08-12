CREATE TABLE IF NOT EXISTS soc_shifts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  shift_name TEXT NOT NULL,
  shift_date DATE NOT NULL DEFAULT CURRENT_DATE,
  start_time TIMESTAMPTZ NOT NULL,
  end_time TIMESTAMPTZ,
  lead_analyst_id UUID,
  team_members JSONB NOT NULL DEFAULT '[]',
  status TEXT NOT NULL DEFAULT 'active',
  handover_notes TEXT NOT NULL DEFAULT '',
  open_incidents JSONB NOT NULL DEFAULT '[]',
  pending_tasks JSONB NOT NULL DEFAULT '[]',
  metrics JSONB NOT NULL DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_soc_shifts_date ON soc_shifts(shift_date DESC);
CREATE INDEX IF NOT EXISTS idx_soc_shifts_status ON soc_shifts(status);
