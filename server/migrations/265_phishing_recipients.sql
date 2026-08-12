-- 265: Phishing simulation recipients — per-target tracking for real sends.
-- Each row is one recipient of a phishing campaign with an unguessable token used
-- by the public tracking endpoints (open pixel / click redirect / report). Campaign
-- counts and analytics are derived from this table at request time.

CREATE TABLE IF NOT EXISTS phishing_recipients (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL,
    campaign_id UUID NOT NULL REFERENCES phishing_campaigns(id) ON DELETE CASCADE,
    email       TEXT NOT NULL,
    department  TEXT NOT NULL DEFAULT '',
    token       TEXT NOT NULL UNIQUE,
    sent        BOOLEAN NOT NULL DEFAULT FALSE,
    sent_at     TIMESTAMPTZ,
    opened      BOOLEAN NOT NULL DEFAULT FALSE,
    opened_at   TIMESTAMPTZ,
    clicked     BOOLEAN NOT NULL DEFAULT FALSE,
    clicked_at  TIMESTAMPTZ,
    reported    BOOLEAN NOT NULL DEFAULT FALSE,
    reported_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_phishing_recipients_campaign ON phishing_recipients(campaign_id);
CREATE INDEX IF NOT EXISTS idx_phishing_recipients_token ON phishing_recipients(token);
CREATE INDEX IF NOT EXISTS idx_phishing_recipients_tenant ON phishing_recipients(tenant_id);

-- Landing page to redirect a clicked recipient to (empty = built-in awareness page).
ALTER TABLE phishing_campaigns ADD COLUMN IF NOT EXISTS landing_page TEXT NOT NULL DEFAULT '';
