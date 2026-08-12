-- 160: periodic access review / user access certification
CREATE TABLE IF NOT EXISTS access_review_campaigns (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL,
    description TEXT,
    reviewer_id UUID REFERENCES users(id) ON DELETE SET NULL,
    status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','active','completed','cancelled')),
    scope JSONB DEFAULT '{}',
    due_date TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS access_review_items (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    campaign_id UUID REFERENCES access_review_campaigns(id) ON DELETE CASCADE,
    subject_user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    resource TEXT NOT NULL,
    permission TEXT NOT NULL,
    decision TEXT CHECK (decision IN ('approve','revoke','pending')) DEFAULT 'pending',
    decided_by UUID REFERENCES users(id) ON DELETE SET NULL,
    decided_at TIMESTAMPTZ,
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_access_review_campaign ON access_review_items(campaign_id);
CREATE INDEX IF NOT EXISTS idx_access_review_decision ON access_review_items(decision);
