-- Migration 052: Performance Indexes
--
-- Adds missing indexes based on common query patterns observed across the EDR platform.
-- Covers alerts, events, agents, audit_logs, incidents, device_events, fim_events,
-- api_keys, and sessions tables. All indexes use IF NOT EXISTS so this migration is
-- safe to re-run. The fim_events block is guarded with a DO $$ check to handle
-- environments where that table has not been created yet.

-- alerts: most common query patterns
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_agent_id_created ON alerts(agent_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_severity_status ON alerts(severity, status);
CREATE INDEX IF NOT EXISTS idx_alerts_tenant_created ON alerts(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_mitre ON alerts(mitre_technique) WHERE mitre_technique IS NOT NULL;

-- events: time-series queries (column names: event_type, time — not type/created_at)
CREATE INDEX IF NOT EXISTS idx_events_agent_type ON events(agent_id, event_type);
CREATE INDEX IF NOT EXISTS idx_events_time ON events(time DESC);
CREATE INDEX IF NOT EXISTS idx_events_agent_time ON events(agent_id, time DESC);
CREATE INDEX IF NOT EXISTS idx_events_type_time ON events(event_type, time DESC);

-- agents: status + last_seen queries
CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status);
CREATE INDEX IF NOT EXISTS idx_agents_last_seen ON agents(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_agents_tenant_status ON agents(tenant_id, status);

-- audit_logs: created_at is added in migration 173; use timestamp for now.
-- tenant_id is not on audit_logs; skip that index.
CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_ts ON audit_logs(user_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);

-- incidents: status + severity
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_incidents_tenant_status ON incidents(tenant_id, status);

-- device_events: agent + time
CREATE INDEX IF NOT EXISTS idx_device_events_agent ON device_events(agent_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_device_events_action ON device_events(action);

-- fim_events / fim-related events: if table exists
-- (guarded with DO $$ to handle missing table gracefully)
DO $$ BEGIN
  IF EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'fim_events') THEN
    EXECUTE 'CREATE INDEX IF NOT EXISTS idx_fim_events_agent ON fim_events(agent_id, created_at DESC)';
  END IF;
END $$;

-- api_keys: lookup by hash (already unique, but explicit)
CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id);

-- sessions: table is user_sessions; revoked is a BOOLEAN column (no revoked_at)
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON user_sessions(user_id) WHERE NOT revoked;
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON user_sessions(expires_at);
