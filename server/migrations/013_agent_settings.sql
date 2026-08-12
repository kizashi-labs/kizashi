-- Migration 013: Agent deployment settings
-- Adds server_grpc_url setting used in agent deployment instructions

INSERT INTO settings (key, value, description) VALUES
    ('server_grpc_url', '', 'gRPC server URL for agent enrollment (e.g. https://edr.company.com:9090)')
ON CONFLICT (key) DO NOTHING;

-- Add agent_version column to track deployed agent versions
ALTER TABLE agents ADD COLUMN IF NOT EXISTS agent_version TEXT;
