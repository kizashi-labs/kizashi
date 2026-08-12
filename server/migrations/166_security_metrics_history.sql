-- 166: security metrics time-series history
CREATE TABLE IF NOT EXISTS security_metrics_history (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    metric_name TEXT NOT NULL,
    metric_value NUMERIC(18,4) NOT NULL,
    metric_unit TEXT DEFAULT '',
    tags JSONB DEFAULT '{}',
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_metrics_name ON security_metrics_history(metric_name);
CREATE INDEX IF NOT EXISTS idx_metrics_recorded ON security_metrics_history(recorded_at DESC);
CREATE INDEX IF NOT EXISTS idx_metrics_name_recorded ON security_metrics_history(metric_name, recorded_at DESC);
