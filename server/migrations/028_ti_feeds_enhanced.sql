-- Enhanced threat intelligence feed tracking
ALTER TABLE threat_feeds ADD COLUMN IF NOT EXISTS feed_type TEXT NOT NULL DEFAULT 'ip';
ALTER TABLE threat_feeds ADD COLUMN IF NOT EXISTS source_format TEXT NOT NULL DEFAULT 'custom';
ALTER TABLE threat_feeds ADD COLUMN IF NOT EXISTS last_entry_count INT NOT NULL DEFAULT 0;
ALTER TABLE threat_feeds ADD COLUMN IF NOT EXISTS error_message TEXT;
ALTER TABLE threat_feeds ADD COLUMN IF NOT EXISTS api_key TEXT;
ALTER TABLE threat_feeds ADD COLUMN IF NOT EXISTS extra_config JSONB NOT NULL DEFAULT '{}';

-- Feed sync history
CREATE TABLE IF NOT EXISTS threat_feed_sync_history (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    feed_id     UUID NOT NULL,
    synced_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    entry_count INT NOT NULL DEFAULT 0,
    duration_ms INT NOT NULL DEFAULT 0,
    success     BOOLEAN NOT NULL DEFAULT TRUE,
    error       TEXT
);
CREATE INDEX IF NOT EXISTS tf_sync_history_feed_idx ON threat_feed_sync_history(feed_id, synced_at DESC);

-- Pre-seed known threat intel sources
INSERT INTO threat_feeds (name, url, feed_type, source_format, is_active, description) VALUES
('AlienVault OTX - Malicious IPs',     'https://reputation.alienvault.com/reputation.data', 'ip', 'otx_reputation', FALSE, 'AlienVault OTX IP reputation feed'),
('abuse.ch URLhaus',                    'https://urlhaus.abuse.ch/downloads/csv_recent/', 'url', 'urlhaus_csv', FALSE, 'URLhaus malicious URLs feed'),
('abuse.ch MalwareBazaar',              'https://bazaar.abuse.ch/export/csv/recent/', 'hash', 'malwarebazaar_csv', FALSE, 'MalwareBazaar malware hash feed'),
('Feodo Tracker (C2 IPs)',              'https://feodotracker.abuse.ch/downloads/ipblocklist.csv', 'ip', 'feodo_csv', FALSE, 'Feodo Tracker botnet C2 IP blocklist'),
('MISP Community Feed',                 'https://www.circl.lu/doc/misp/feed-osint/', 'composite', 'misp_json', FALSE, 'CIRCL MISP OSINT community feed')
ON CONFLICT DO NOTHING;
