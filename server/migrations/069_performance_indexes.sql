-- Migration 069: Performance indexes for common query patterns
-- NOTE: CONCURRENTLY removed — migrate.go runs each migration inside a transaction,
--       and PostgreSQL forbids CREATE INDEX CONCURRENTLY inside a transaction block.

-- Alert queries (most frequent)
CREATE INDEX IF NOT EXISTS idx_alerts_status_severity
  ON alerts(status, severity DESC) WHERE status != 'resolved';
CREATE INDEX IF NOT EXISTS idx_alerts_agent_created
  ON alerts(agent_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_rule_created
  ON alerts(rule_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_created_severity
  ON alerts(created_at DESC, severity DESC);

-- Agent queries
CREATE INDEX IF NOT EXISTS idx_agents_status_lastseen
  ON agents(status, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_agents_group_status
  ON agents(group_id, status) WHERE group_id IS NOT NULL;

-- Events (TimescaleDB)
CREATE INDEX IF NOT EXISTS idx_events_agent_type_time
  ON events(agent_id, event_type, time DESC);

-- IOC lookups: ioc_entries uses (value, type, is_active) at this migration point.
-- The indicator_value/indicator_type columns belong to enrichment_cache (added in 132).
CREATE INDEX IF NOT EXISTS idx_ioc_entries_value_active
  ON ioc_entries(value, is_active);

-- Audit log: table is audit_logs, timestamp column (not created_at) at this point.
CREATE INDEX IF NOT EXISTS idx_audit_log_user_ts
  ON audit_logs(user_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_action_ts
  ON audit_logs(action, timestamp DESC);

-- Incidents
CREATE INDEX IF NOT EXISTS idx_incidents_status_severity
  ON incidents(status, severity DESC) WHERE status NOT IN ('closed', 'resolved');

-- Suppression rules: at migration 069 the table has is_active (not enabled/rule_type).
-- enabled and rule_type columns are added in later migrations; skip that index here.

-- Sessions: table is user_sessions, no token_hash column (uses jti instead).
CREATE INDEX IF NOT EXISTS idx_user_sessions_expires
  ON user_sessions(expires_at) WHERE NOT revoked;

-- Agent tags (added in 067)
CREATE INDEX IF NOT EXISTS idx_agent_tags_tag_agent
  ON agent_tags(tag, agent_id);
