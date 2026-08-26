CREATE TABLE IF NOT EXISTS container_workloads (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  cluster_name TEXT NOT NULL,
  namespace TEXT NOT NULL DEFAULT 'default',
  workload_type TEXT NOT NULL DEFAULT 'deployment',
  workload_name TEXT NOT NULL,
  image TEXT NOT NULL,
  image_digest TEXT NOT NULL DEFAULT '',
  replicas INT NOT NULL DEFAULT 1,
  ready_replicas INT NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'running',
  risk_score INT NOT NULL DEFAULT 0,
  vulnerabilities JSONB NOT NULL DEFAULT '[]',
  labels JSONB NOT NULL DEFAULT '{}',
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(cluster_name, namespace, workload_name)
);
CREATE INDEX IF NOT EXISTS idx_container_workloads_cluster ON container_workloads(cluster_name);
CREATE INDEX IF NOT EXISTS idx_container_workloads_risk ON container_workloads(risk_score DESC);

CREATE TABLE IF NOT EXISTS container_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workload_id UUID NOT NULL,
  event_type TEXT NOT NULL,
  severity TEXT NOT NULL DEFAULT 'info',
  message TEXT NOT NULL,
  details JSONB NOT NULL DEFAULT '{}',
  occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_container_events_workload ON container_events(workload_id, occurred_at DESC);
