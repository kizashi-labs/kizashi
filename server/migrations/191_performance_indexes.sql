-- Events table performance
CREATE INDEX IF NOT EXISTS idx_events_time_type ON events(time DESC, event_type);
CREATE INDEX IF NOT EXISTS idx_events_agent_time ON events(agent_id, time DESC);
CREATE INDEX IF NOT EXISTS idx_events_type_time ON events(event_type, time DESC);

-- Alerts performance
CREATE INDEX IF NOT EXISTS idx_alerts_status_created ON alerts(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_agent_created ON alerts(agent_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_severity_created ON alerts(severity DESC, created_at DESC);

-- Agents performance
CREATE INDEX IF NOT EXISTS idx_agents_last_seen ON agents(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status);

-- Composite for dashboard queries
CREATE INDEX IF NOT EXISTS idx_alerts_created_status_sev ON alerts(created_at DESC, status, severity);
