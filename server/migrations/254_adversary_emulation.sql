-- Adversary Emulation: MITRE ATT&CK ベースの敵対的エミュレーション計画と実行記録。
-- ネストした構造（actor_profile / phases / techniques / preconditions など）は
-- 全体を読み書きするため JSONB で保持する。

CREATE TABLE IF NOT EXISTS emulation_plans (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    plan_name             TEXT NOT NULL,
    threat_actor_based_on TEXT NOT NULL DEFAULT '',
    actor_profile         JSONB NOT NULL DEFAULT '{}'::jsonb,
    scope                 TEXT NOT NULL DEFAULT '',
    status                TEXT NOT NULL DEFAULT 'draft', -- draft, approved, in_progress, completed, archived
    created_by            TEXT NOT NULL DEFAULT '',
    last_executed         TIMESTAMPTZ,
    phases                JSONB NOT NULL DEFAULT '[]'::jsonb,
    target_systems        JSONB NOT NULL DEFAULT '[]'::jsonb,
    excluded_systems      JSONB NOT NULL DEFAULT '[]'::jsonb,
    time_window           TEXT NOT NULL DEFAULT '',
    rules_of_engagement   TEXT NOT NULL DEFAULT '',
    preconditions         JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_emulation_plans_created ON emulation_plans(created_at DESC);

CREATE TABLE IF NOT EXISTS emulation_executions (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    plan_id                 UUID NOT NULL REFERENCES emulation_plans(id) ON DELETE CASCADE,
    plan_name               TEXT NOT NULL DEFAULT '',
    executed_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    executed_by             TEXT NOT NULL DEFAULT '',
    duration_minutes        INTEGER NOT NULL DEFAULT 0,
    phases_completed        INTEGER NOT NULL DEFAULT 0,
    phases_total            INTEGER NOT NULL DEFAULT 0,
    detections_count        INTEGER NOT NULL DEFAULT 0,
    missed_detections_count INTEGER NOT NULL DEFAULT 0,
    detection_rate          NUMERIC(6,2) NOT NULL DEFAULT 0,
    phase_results           JSONB NOT NULL DEFAULT '[]'::jsonb,
    gap_analysis            JSONB NOT NULL DEFAULT '[]'::jsonb,
    notes                   TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_emulation_exec_plan ON emulation_executions(plan_id, executed_at DESC);
