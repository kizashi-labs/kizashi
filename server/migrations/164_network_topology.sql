-- 164: network topology mapping
CREATE TABLE IF NOT EXISTS network_topology_nodes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id UUID REFERENCES agents(id) ON DELETE SET NULL,
    node_type TEXT NOT NULL DEFAULT 'endpoint' CHECK (node_type IN ('endpoint','server','router','switch','firewall','cloud','unknown')),
    name TEXT NOT NULL,
    ip_addresses INET[] DEFAULT '{}',
    mac_address TEXT,
    os_info TEXT,
    department TEXT,
    criticality TEXT NOT NULL DEFAULT 'medium' CHECK (criticality IN ('critical','high','medium','low')),
    x_pos NUMERIC(10,2) DEFAULT 0,
    y_pos NUMERIC(10,2) DEFAULT 0,
    metadata JSONB DEFAULT '{}',
    last_seen TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS network_topology_edges (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    source_node_id UUID REFERENCES network_topology_nodes(id) ON DELETE CASCADE,
    target_node_id UUID REFERENCES network_topology_nodes(id) ON DELETE CASCADE,
    edge_type TEXT NOT NULL DEFAULT 'connection' CHECK (edge_type IN ('connection','depends_on','communicates_with','tunnels_to')),
    protocol TEXT,
    port INT,
    bytes_sent BIGINT DEFAULT 0,
    bytes_received BIGINT DEFAULT 0,
    last_seen TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_topo_nodes_agent ON network_topology_nodes(agent_id);
CREATE INDEX IF NOT EXISTS idx_topo_nodes_type ON network_topology_nodes(node_type);
CREATE INDEX IF NOT EXISTS idx_topo_edges_source ON network_topology_edges(source_node_id);
CREATE INDEX IF NOT EXISTS idx_topo_edges_target ON network_topology_edges(target_node_id);
