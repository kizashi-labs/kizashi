-- TimescaleDB hypertable for high-volume endpoint events
-- Partition by time (7-day chunks), auto-compress after 30 days

-- ─── Raw Events Table ─────────────────────────────────────────

CREATE TABLE events (
    time         TIMESTAMPTZ      NOT NULL,
    agent_id     UUID             NOT NULL,
    event_id     UUID             NOT NULL DEFAULT uuid_generate_v4(),
    event_type   TEXT             NOT NULL
                     CHECK (event_type IN ('process', 'file', 'network',
                                           'dns', 'registry', 'auth')),
    severity     SMALLINT         DEFAULT 0,
    anomaly_score FLOAT           DEFAULT 0.0,
    raw_data     JSONB            NOT NULL,    -- full event payload
    rule_matches TEXT[],                       -- matched rule IDs
    alert_id     UUID                          -- linked alert if any
);

-- Convert to hypertable (partitioned by time, 7-day chunks)
SELECT create_hypertable('events', 'time',
    chunk_time_interval => INTERVAL '7 days'
);

-- Indexes
CREATE INDEX ON events (agent_id, time DESC);
CREATE INDEX ON events (event_type, time DESC);
CREATE INDEX ON events (alert_id) WHERE alert_id IS NOT NULL;
CREATE INDEX ON events USING GIN (raw_data jsonb_path_ops);

-- Enable compression (after 30 days, ~10:1 ratio)
ALTER TABLE events SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'agent_id,event_type',
    timescaledb.compress_orderby = 'time DESC'
);

SELECT add_compression_policy('events', INTERVAL '30 days');

-- Data retention: keep raw events for 90 days
SELECT add_retention_policy('events', INTERVAL '90 days');

-- ─── Continuous Aggregates (for dashboard queries) ─────────────

-- Hourly event counts per agent (pre-computed for fast dashboard)
CREATE MATERIALIZED VIEW events_hourly
WITH (timescaledb.continuous) AS
SELECT
    time_bucket('1 hour', time)    AS bucket,
    agent_id,
    event_type,
    COUNT(*)                       AS event_count,
    MAX(severity)                  AS max_severity,
    MAX(anomaly_score)             AS max_anomaly_score,
    COUNT(*) FILTER (WHERE array_length(rule_matches, 1) > 0) AS matched_count
FROM events
GROUP BY bucket, agent_id, event_type
WITH NO DATA;

SELECT add_continuous_aggregate_policy('events_hourly',
    start_offset => INTERVAL '3 days',
    end_offset   => INTERVAL '1 hour',
    schedule_interval => INTERVAL '1 hour'
);

-- Keep hourly aggregates for 1 year
SELECT add_retention_policy('events_hourly', INTERVAL '365 days');

-- Daily summary per agent
CREATE MATERIALIZED VIEW events_daily
WITH (timescaledb.continuous) AS
SELECT
    time_bucket('1 day', time)     AS bucket,
    agent_id,
    COUNT(*)                       AS total_events,
    COUNT(DISTINCT event_type)     AS event_types,
    MAX(severity)                  AS max_severity,
    SUM(CASE WHEN event_type = 'process' THEN 1 ELSE 0 END)  AS process_events,
    SUM(CASE WHEN event_type = 'network' THEN 1 ELSE 0 END)  AS network_events,
    SUM(CASE WHEN event_type = 'file'    THEN 1 ELSE 0 END)  AS file_events
FROM events
GROUP BY bucket, agent_id
WITH NO DATA;

SELECT add_continuous_aggregate_policy('events_daily',
    start_offset => INTERVAL '7 days',
    end_offset   => INTERVAL '1 day',
    schedule_interval => INTERVAL '1 day'
);

SELECT add_retention_policy('events_daily', INTERVAL '730 days');

-- ─── Network Connections Table ────────────────────────────────

CREATE TABLE network_connections (
    time         TIMESTAMPTZ NOT NULL,
    agent_id     UUID        NOT NULL,
    src_ip       INET,
    src_port     INTEGER,
    dst_ip       INET        NOT NULL,
    dst_port     INTEGER     NOT NULL,
    protocol     TEXT,
    direction    TEXT,
    bytes_sent   BIGINT      DEFAULT 0,
    bytes_recv   BIGINT      DEFAULT 0,
    pid          INTEGER,
    process_name TEXT,
    hostname     TEXT,
    country_code TEXT,
    is_suspicious BOOLEAN    DEFAULT FALSE,
    alert_id     UUID
);

SELECT create_hypertable('network_connections', 'time',
    chunk_time_interval => INTERVAL '1 day'
);

CREATE INDEX ON network_connections (agent_id, time DESC);
CREATE INDEX ON network_connections (dst_ip, time DESC);
CREATE INDEX ON network_connections (is_suspicious) WHERE is_suspicious = TRUE;

ALTER TABLE network_connections SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'agent_id',
    timescaledb.compress_orderby = 'time DESC'
);
SELECT add_compression_policy('network_connections', INTERVAL '7 days');
SELECT add_retention_policy('network_connections', INTERVAL '30 days');
