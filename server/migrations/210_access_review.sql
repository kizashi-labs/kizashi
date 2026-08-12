-- Migration 210: Access Review Campaigns
-- B-02: Periodic user access review (campaign-based)

CREATE TABLE IF NOT EXISTS access_review_campaigns (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name        TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  status      TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','active','completed','cancelled')),
  reviewer    TEXT NOT NULL,
  due_date    DATE NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS access_review_items (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  campaign_id UUID NOT NULL REFERENCES access_review_campaigns(id) ON DELETE CASCADE,
  user_name   TEXT NOT NULL,
  resource    TEXT NOT NULL,
  permission  TEXT NOT NULL,
  decision    TEXT NOT NULL DEFAULT 'pending' CHECK (decision IN ('pending','approve','revoke')),
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_access_review_items_campaign ON access_review_items(campaign_id);
