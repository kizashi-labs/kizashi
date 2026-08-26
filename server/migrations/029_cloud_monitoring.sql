-- Cloud workload monitoring
CREATE TABLE IF NOT EXISTS cloud_integrations (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL,
    provider    TEXT NOT NULL,   -- aws | azure | gcp
    region      TEXT NOT NULL DEFAULT '',
    config      JSONB NOT NULL DEFAULT '{}',
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    last_synced_at TIMESTAMPTZ,
    error_message  TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS cloud_events (
    id          TEXT NOT NULL,
    integration_id UUID NOT NULL REFERENCES cloud_integrations(id) ON DELETE CASCADE,
    provider    TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    event_time  TIMESTAMPTZ NOT NULL,
    source_ip   TEXT,
    user_identity JSONB,
    resource    TEXT,
    region      TEXT,
    raw_event   JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (id, event_time)
);
SELECT create_hypertable('cloud_events', 'event_time', if_not_exists => TRUE);
CREATE INDEX IF NOT EXISTS cloud_events_integration_idx ON cloud_events(integration_id, event_time DESC);
CREATE INDEX IF NOT EXISTS cloud_events_type_idx ON cloud_events(event_type, event_time DESC);

-- Pre-seed example integrations (disabled by default)
INSERT INTO cloud_integrations (name, provider, region, config, enabled) VALUES
('AWS CloudTrail (Example)', 'aws', 'us-east-1',
 '{"access_key_id": "", "secret_access_key": "", "s3_bucket": "", "trail_name": ""}',
 FALSE),
('Azure Activity Log (Example)', 'azure', 'eastus',
 '{"tenant_id": "", "client_id": "", "client_secret": "", "subscription_id": ""}',
 FALSE)
ON CONFLICT DO NOTHING;
