-- プロセス実行ベースライン (異常検知用)
CREATE TABLE IF NOT EXISTS process_baselines (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id    UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    process_name TEXT NOT NULL,
    hour_of_day  SMALLINT NOT NULL CHECK (hour_of_day BETWEEN 0 AND 23),
    exec_count   INTEGER NOT NULL DEFAULT 0,  -- 過去7日の当該時間帯の実行回数
    avg_count    FLOAT NOT NULL DEFAULT 0,    -- 1日あたりの平均実行回数
    std_dev      FLOAT NOT NULL DEFAULT 0,    -- 標準偏差
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (agent_id, process_name, hour_of_day)  -- UPSERTで使用
);

-- 異常スコア履歴
CREATE TABLE IF NOT EXISTS anomaly_scores (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id     UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    process_name TEXT NOT NULL,
    z_score      FLOAT NOT NULL,
    hour_of_day  SMALLINT NOT NULL,
    event_count  INTEGER NOT NULL,
    detected_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_anomaly_agent ON anomaly_scores(agent_id, detected_at DESC);
