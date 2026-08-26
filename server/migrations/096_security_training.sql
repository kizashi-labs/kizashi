CREATE TABLE IF NOT EXISTS training_campaigns (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  campaign_type TEXT NOT NULL DEFAULT 'phishing_simulation',
  status TEXT NOT NULL DEFAULT 'draft',
  target_count INT NOT NULL DEFAULT 0,
  sent_count INT NOT NULL DEFAULT 0,
  opened_count INT NOT NULL DEFAULT 0,
  clicked_count INT NOT NULL DEFAULT 0,
  reported_count INT NOT NULL DEFAULT 0,
  scheduled_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  created_by UUID,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS training_results (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  campaign_id UUID NOT NULL,
  user_id UUID,
  email TEXT NOT NULL,
  action TEXT NOT NULL DEFAULT 'none',
  action_at TIMESTAMPTZ,
  completed_training BOOL NOT NULL DEFAULT FALSE,
  training_score INT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_training_results_campaign ON training_results(campaign_id);
