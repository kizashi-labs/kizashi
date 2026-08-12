CREATE TABLE IF NOT EXISTS software_inventory_snapshots (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id UUID NOT NULL,
  snapshot_date DATE NOT NULL DEFAULT CURRENT_DATE,
  software_count INT NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(agent_id, snapshot_date)
);

CREATE TABLE IF NOT EXISTS software_inventory_diffs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id UUID NOT NULL,
  diff_date DATE NOT NULL DEFAULT CURRENT_DATE,
  added JSONB NOT NULL DEFAULT '[]',
  removed JSONB NOT NULL DEFAULT '[]',
  added_count INT NOT NULL DEFAULT 0,
  removed_count INT NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_sw_diffs_agent_date ON software_inventory_diffs(agent_id, diff_date DESC);
