-- 172: security awareness training tracking
CREATE TABLE IF NOT EXISTS awareness_courses (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    title TEXT NOT NULL,
    description TEXT,
    category TEXT NOT NULL DEFAULT 'general',
    duration_minutes INT NOT NULL DEFAULT 30,
    difficulty TEXT NOT NULL DEFAULT 'beginner' CHECK (difficulty IN ('beginner','intermediate','advanced')),
    passing_score INT NOT NULL DEFAULT 80,
    mandatory BOOLEAN NOT NULL DEFAULT false,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS awareness_enrollments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    course_id UUID REFERENCES awareness_courses(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'enrolled' CHECK (status IN ('enrolled','in_progress','completed','failed','expired')),
    score INT,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    due_date TIMESTAMPTZ,
    attempts INT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(course_id, user_id)
);
CREATE TABLE IF NOT EXISTS phishing_simulations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL,
    template TEXT NOT NULL DEFAULT 'generic',
    target_count INT NOT NULL DEFAULT 0,
    sent_count INT NOT NULL DEFAULT 0,
    opened_count INT NOT NULL DEFAULT 0,
    clicked_count INT NOT NULL DEFAULT 0,
    reported_count INT NOT NULL DEFAULT 0,
    credentials_entered INT NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','running','completed','cancelled')),
    scheduled_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_awareness_enrollments_course ON awareness_enrollments(course_id);
CREATE INDEX IF NOT EXISTS idx_awareness_enrollments_user ON awareness_enrollments(user_id);
CREATE INDEX IF NOT EXISTS idx_awareness_enrollments_status ON awareness_enrollments(status);
CREATE INDEX IF NOT EXISTS idx_phishing_sims_status ON phishing_simulations(status);
