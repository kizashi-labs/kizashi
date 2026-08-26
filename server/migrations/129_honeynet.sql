CREATE TABLE IF NOT EXISTS honeynet_nodes (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name           VARCHAR(255) NOT NULL,
  node_type      VARCHAR(100) NOT NULL,  -- honeypot, honeytoken, honeydomain, honeyuser, honeyservice
  ip_address     INET,
  hostname       VARCHAR(255),
  os_profile     VARCHAR(100),  -- windows_server, linux_ubuntu, network_device, printer
  services       JSONB NOT NULL DEFAULT '[]',  -- [{port, protocol, banner}]
  is_active      BOOLEAN NOT NULL DEFAULT true,
  interaction_count INT NOT NULL DEFAULT 0,
  last_interaction TIMESTAMPTZ,
  network_segment VARCHAR(100),
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS honeynet_interactions (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  node_id        UUID NOT NULL REFERENCES honeynet_nodes(id) ON DELETE CASCADE,
  attacker_ip    INET NOT NULL,
  attacker_port  INT,
  protocol       VARCHAR(50),
  payload        TEXT,
  commands       JSONB NOT NULL DEFAULT '[]',
  files_accessed JSONB NOT NULL DEFAULT '[]',
  session_duration_s INT NOT NULL DEFAULT 0,
  threat_level   VARCHAR(50) NOT NULL DEFAULT 'medium',
  geo_country    VARCHAR(100),
  is_automated   BOOLEAN NOT NULL DEFAULT false,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_honeynet_interactions_node ON honeynet_interactions(node_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_honeynet_interactions_ip ON honeynet_interactions(attacker_ip);
