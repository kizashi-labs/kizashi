CREATE TABLE IF NOT EXISTS security_metrics (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  metric_name TEXT NOT NULL,
  metric_value DOUBLE PRECISION NOT NULL,
  dimensions JSONB NOT NULL DEFAULT '{}',
  recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_metrics_name_time ON security_metrics(metric_name, recorded_at DESC);
CREATE INDEX IF NOT EXISTS idx_metrics_time ON security_metrics(recorded_at DESC);

CREATE TABLE IF NOT EXISTS metric_aggregates (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  metric_name TEXT NOT NULL,
  period TEXT NOT NULL DEFAULT 'hourly',
  period_start TIMESTAMPTZ NOT NULL,
  avg_value DOUBLE PRECISION NOT NULL DEFAULT 0,
  min_value DOUBLE PRECISION NOT NULL DEFAULT 0,
  max_value DOUBLE PRECISION NOT NULL DEFAULT 0,
  sum_value DOUBLE PRECISION NOT NULL DEFAULT 0,
  count INT NOT NULL DEFAULT 0,
  UNIQUE(metric_name, period, period_start)
);
CREATE INDEX IF NOT EXISTS idx_agg_name_period ON metric_aggregates(metric_name, period, period_start DESC);
