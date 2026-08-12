CREATE TABLE IF NOT EXISTS security_budget_items (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  fiscal_year INT NOT NULL,
  category    VARCHAR(100) NOT NULL,  -- tools, personnel, training, incident_response, compliance
  name        VARCHAR(255) NOT NULL,
  allocated   NUMERIC(15,2) NOT NULL DEFAULT 0,
  spent       NUMERIC(15,2) NOT NULL DEFAULT 0,
  vendor      VARCHAR(255),
  notes       TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS security_budget_transactions (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  budget_item_id UUID NOT NULL REFERENCES security_budget_items(id) ON DELETE CASCADE,
  amount      NUMERIC(15,2) NOT NULL,
  description TEXT,
  date        DATE NOT NULL DEFAULT CURRENT_DATE,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
