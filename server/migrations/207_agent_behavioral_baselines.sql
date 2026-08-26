-- エージェントごとのベースラインをDBに永続化する
CREATE TABLE IF NOT EXISTS agent_behavioral_baselines (
    id                    UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id              UUID        NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    baseline_status       TEXT        NOT NULL DEFAULT 'learning'
                              CHECK (baseline_status IN
                                     ('established','learning','insufficient_data','anomalous')),
    learning_started      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    data_points_collected BIGINT      NOT NULL DEFAULT 0,
    last_updated          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    anomaly_count         INTEGER     NOT NULL DEFAULT 0,
    confidence_score      SMALLINT    NOT NULL DEFAULT 0
                              CHECK (confidence_score BETWEEN 0 AND 100),
    -- 7 x 24 アクティビティヒートマップ (0-100 の数値配列)
    active_hours          JSONB       NOT NULL DEFAULT '[]',
    -- [{"name":"chrome.exe","frequency":98,"is_rare":false}, ...]
    typical_processes     JSONB       NOT NULL DEFAULT '[]',
    -- [{"host":"office365.com","port":443,"protocol":"HTTPS","volume_mb":840}, ...]
    typical_destinations  JSONB       NOT NULL DEFAULT '[]',
    -- ["/var/lib/mysql", ...]
    typical_directories   JSONB       NOT NULL DEFAULT '[]',
    -- [{"id":"...","category":"Process","description":"...","severity":"high","detected_at":"..."}, ...]
    recent_deviations     JSONB       NOT NULL DEFAULT '[]',
    -- ["C:\\Windows\\Temp\\update*.exe", ...]
    exclusion_rules       JSONB       NOT NULL DEFAULT '[]',
    UNIQUE (agent_id)
);

CREATE INDEX IF NOT EXISTS idx_agent_behavioral_baselines_agent
    ON agent_behavioral_baselines(agent_id);
CREATE INDEX IF NOT EXISTS idx_agent_behavioral_baselines_status
    ON agent_behavioral_baselines(baseline_status);

-- ベースライン設定をsettingsテーブルに追加
INSERT INTO settings (key, value, description) VALUES
    ('baseline_learning_period_days', '30',   'ベースライン学習期間（日数）'),
    ('baseline_confidence_threshold', '0.85', 'established に昇格する最小信頼スコア'),
    ('baseline_auto_alert',           'true', '逸脱検知時に自動アラートを発報するか'),
    ('baseline_deviation_sensitivity','medium','感度: low|medium|high|critical')
ON CONFLICT (key) DO NOTHING;
