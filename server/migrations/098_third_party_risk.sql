CREATE TABLE IF NOT EXISTS third_party_vendors (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  category TEXT NOT NULL DEFAULT 'software',
  website TEXT NOT NULL DEFAULT '',
  contact_email TEXT NOT NULL DEFAULT '',
  risk_score INT NOT NULL DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
  risk_tier TEXT NOT NULL DEFAULT 'low',
  last_assessment_at TIMESTAMPTZ,
  next_assessment_due DATE,
  status TEXT NOT NULL DEFAULT 'active',
  notes TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_vendors_risk ON third_party_vendors(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_vendors_tier ON third_party_vendors(risk_tier);

CREATE TABLE IF NOT EXISTS vendor_assessments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  vendor_id UUID NOT NULL REFERENCES third_party_vendors(id) ON DELETE CASCADE,
  assessor_id UUID,
  scores JSONB NOT NULL DEFAULT '{}',
  overall_score INT NOT NULL DEFAULT 0,
  findings TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'draft',
  assessed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_vendor_assessments_vendor ON vendor_assessments(vendor_id);
