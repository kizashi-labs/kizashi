-- 170: email security monitoring
CREATE TABLE IF NOT EXISTS email_security_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    message_id TEXT,
    sender TEXT NOT NULL,
    recipient TEXT NOT NULL,
    subject TEXT,
    event_type TEXT NOT NULL DEFAULT 'threat' CHECK (event_type IN ('phishing','malware','spam','bec','data_leak','suspicious','clean')),
    threat_score INT NOT NULL DEFAULT 0 CHECK (threat_score BETWEEN 0 AND 100),
    action_taken TEXT NOT NULL DEFAULT 'quarantined' CHECK (action_taken IN ('blocked','quarantined','tagged','allowed','reported')),
    attachments JSONB DEFAULT '[]',
    urls JSONB DEFAULT '[]',
    headers JSONB DEFAULT '{}',
    source_ip INET,
    alert_id UUID REFERENCES alerts(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS email_security_policies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL,
    description TEXT,
    policy_type TEXT NOT NULL DEFAULT 'inbound' CHECK (policy_type IN ('inbound','outbound','internal')),
    conditions JSONB DEFAULT '{}',
    action TEXT NOT NULL DEFAULT 'quarantine' CHECK (action IN ('block','quarantine','tag','allow','report')),
    priority INT NOT NULL DEFAULT 100,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
-- 094 created email_security_events without event_type, threat_score, created_at; add before indexing
ALTER TABLE email_security_events ADD COLUMN IF NOT EXISTS event_type   TEXT NOT NULL DEFAULT 'threat';
ALTER TABLE email_security_events ADD COLUMN IF NOT EXISTS threat_score INT  NOT NULL DEFAULT 0;
ALTER TABLE email_security_events ADD COLUMN IF NOT EXISTS created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW();

CREATE INDEX IF NOT EXISTS idx_email_events_type ON email_security_events(event_type);
CREATE INDEX IF NOT EXISTS idx_email_events_score ON email_security_events(threat_score DESC);
CREATE INDEX IF NOT EXISTS idx_email_events_created ON email_security_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_email_events_sender ON email_security_events(sender);
