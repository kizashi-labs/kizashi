CREATE TABLE IF NOT EXISTS agent_policies (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    tenant_id       UUID REFERENCES tenants(id) ON DELETE CASCADE,
    -- スキャン設定
    scan_interval_min INTEGER NOT NULL DEFAULT 60,  -- スキャン間隔（分）
    full_scan_hour    SMALLINT NOT NULL DEFAULT 2,   -- フルスキャン実行時刻（時）
    -- 監視対象
    monitored_extensions TEXT[] NOT NULL DEFAULT ARRAY['.exe','.dll','.sh','.ps1','.py'],
    excluded_paths       TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    -- リソース制限
    cpu_limit_pct   SMALLINT NOT NULL DEFAULT 20,   -- CPU使用率上限(%)
    mem_limit_mb    INTEGER NOT NULL DEFAULT 256,   -- メモリ上限(MB)
    -- ネットワーク監視
    monitor_network BOOLEAN NOT NULL DEFAULT TRUE,
    monitor_dns     BOOLEAN NOT NULL DEFAULT TRUE,
    -- ログ設定
    log_level       TEXT NOT NULL DEFAULT 'info' CHECK (log_level IN ('debug','info','warn','error')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- デフォルトポリシー
INSERT INTO agent_policies (id, name, description)
VALUES ('00000000-0000-0000-0000-000000000002', 'Default Policy', 'デフォルトエージェントポリシー')
ON CONFLICT DO NOTHING;

-- agent_groups にポリシーを関連付け
ALTER TABLE agent_groups ADD COLUMN IF NOT EXISTS policy_id UUID REFERENCES agent_policies(id) ON DELETE SET NULL;
ALTER TABLE agent_groups ALTER COLUMN policy_id SET DEFAULT '00000000-0000-0000-0000-000000000002';

CREATE INDEX idx_policies_tenant ON agent_policies(tenant_id);
