-- 152: Intelligent Alert Routing
CREATE TABLE IF NOT EXISTS alert_routing_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    priority INTEGER NOT NULL DEFAULT 100,
    conditions JSONB NOT NULL DEFAULT '{}',
    destinations JSONB NOT NULL DEFAULT '[]',
    enrichment_actions JSONB DEFAULT '[]',
    suppression_window_seconds INTEGER DEFAULT 0,
    enabled BOOLEAN DEFAULT true,
    match_count BIGINT DEFAULT 0,
    last_matched_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS alert_routing_destinations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    destination_type VARCHAR(50) NOT NULL CHECK (destination_type IN ('slack','email','pagerduty','servicenow','jira','webhook','sms','teams')),
    config JSONB NOT NULL DEFAULT '{}',
    enabled BOOLEAN DEFAULT true,
    last_used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_alert_routing_rules_tenant ON alert_routing_rules(tenant_id);
CREATE INDEX IF NOT EXISTS idx_alert_routing_rules_priority ON alert_routing_rules(priority ASC);
CREATE INDEX IF NOT EXISTS idx_alert_routing_destinations_tenant ON alert_routing_destinations(tenant_id);
