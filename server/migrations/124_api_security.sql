CREATE TABLE IF NOT EXISTS api_endpoints (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  service_name   VARCHAR(255) NOT NULL,
  method         VARCHAR(10) NOT NULL,
  path           VARCHAR(1000) NOT NULL,
  auth_type      VARCHAR(100),  -- none, api_key, jwt, oauth2, basic
  rate_limit     INT,
  is_public      BOOLEAN NOT NULL DEFAULT false,
  risk_score     INT NOT NULL DEFAULT 0,
  last_scanned   TIMESTAMPTZ,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS api_vulnerabilities (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  endpoint_id    UUID NOT NULL REFERENCES api_endpoints(id) ON DELETE CASCADE,
  vuln_type      VARCHAR(100) NOT NULL,  -- broken_auth, injection, excessive_data, bola, ssrf, etc.
  severity       VARCHAR(50) NOT NULL,
  description    TEXT,
  remediation    TEXT,
  status         VARCHAR(50) NOT NULL DEFAULT 'open',
  owasp_category VARCHAR(100),
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_api_vulns_endpoint ON api_vulnerabilities(endpoint_id);
CREATE TABLE IF NOT EXISTS api_scan_jobs (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  target_url     VARCHAR(1000) NOT NULL,
  scan_type      VARCHAR(100) NOT NULL DEFAULT 'passive',  -- passive, active, fuzz
  status         VARCHAR(50) NOT NULL DEFAULT 'pending',
  endpoints_found INT NOT NULL DEFAULT 0,
  vulns_found    INT NOT NULL DEFAULT 0,
  started_at     TIMESTAMPTZ,
  completed_at   TIMESTAMPTZ,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
