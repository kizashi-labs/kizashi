CREATE TABLE IF NOT EXISTS enrichment_sources (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name           VARCHAR(255) NOT NULL,
  source_type    VARCHAR(100) NOT NULL,  -- virustotal, shodan, whois, geoip, threat_intel, internal
  api_key_masked VARCHAR(255),
  is_active      BOOLEAN NOT NULL DEFAULT true,
  requests_today INT NOT NULL DEFAULT 0,
  daily_limit    INT NOT NULL DEFAULT 1000,
  avg_latency_ms INT NOT NULL DEFAULT 200,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS enrichment_cache (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  indicator_type VARCHAR(50) NOT NULL,  -- ip, domain, hash, url, email
  indicator_value VARCHAR(1000) NOT NULL,
  source         VARCHAR(100) NOT NULL,
  result         JSONB NOT NULL DEFAULT '{}',
  expires_at     TIMESTAMPTZ NOT NULL,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(indicator_value, source)
);
CREATE INDEX IF NOT EXISTS idx_enrichment_cache_indicator ON enrichment_cache(indicator_value, indicator_type);
