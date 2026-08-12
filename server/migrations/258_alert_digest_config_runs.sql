-- 258: Alert digest — persisted config (singleton) and send history.

CREATE TABLE IF NOT EXISTS alert_digest_config (
    id         INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    config     JSONB NOT NULL DEFAULT '{}',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS alert_digest_runs (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type             TEXT NOT NULL CHECK (type IN ('daily','weekly')),
    sent_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    recipients_count INTEGER NOT NULL DEFAULT 0,
    total_alerts     INTEGER NOT NULL DEFAULT 0,
    status           TEXT NOT NULL DEFAULT 'delivered' CHECK (status IN ('delivered','failed','partial'))
);

CREATE INDEX IF NOT EXISTS idx_digest_runs_sent ON alert_digest_runs(sent_at DESC);
