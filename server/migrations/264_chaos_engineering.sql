-- 264: Security chaos engineering — experiment catalog, runs, and approvals.
-- Backs the /admin/chaos-engineering page. Experiments are reusable definitions
-- (hypothesis / blast radius / rollback steps); a run records one execution and
-- an approval request gates risky experiments.

CREATE TABLE IF NOT EXISTS chaos_experiments (
    id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id              UUID NOT NULL,
    name                   TEXT NOT NULL,
    category               TEXT NOT NULL DEFAULT 'network'
                               CHECK (category IN ('network','endpoint','auth','data','detection')),
    description            TEXT NOT NULL DEFAULT '',
    severity_impact        TEXT NOT NULL DEFAULT 'low'
                               CHECK (severity_impact IN ('low','medium','high','critical')),
    target_type            TEXT NOT NULL DEFAULT 'agent'
                               CHECK (target_type IN ('agent','network','auth_service','logging')),
    estimated_duration_min INTEGER NOT NULL DEFAULT 30,
    is_safe                TEXT NOT NULL DEFAULT 'safe'
                               CHECK (is_safe IN ('safe','moderate_risk','high_risk')),
    hypothesis             TEXT NOT NULL DEFAULT '',
    blast_radius           TEXT NOT NULL DEFAULT '',
    rollback_procedure     JSONB NOT NULL DEFAULT '[]',
    steady_state_metrics   JSONB NOT NULL DEFAULT '[]',
    execution_steps        JSONB NOT NULL DEFAULT '[]',
    created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_chaos_experiments_tenant ON chaos_experiments(tenant_id);

CREATE TABLE IF NOT EXISTS chaos_runs (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         UUID NOT NULL,
    experiment_id     UUID NOT NULL,
    experiment_name   TEXT NOT NULL DEFAULT '',
    executed_by       TEXT NOT NULL DEFAULT '',
    started_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    duration_min      INTEGER NOT NULL DEFAULT 0,
    scope             TEXT NOT NULL DEFAULT '',
    result            TEXT NOT NULL DEFAULT 'inconclusive'
                          CHECK (result IN ('hypothesis_confirmed','hypothesis_rejected','inconclusive','aborted')),
    findings_summary  TEXT NOT NULL DEFAULT '',
    hypothesis_actual TEXT NOT NULL DEFAULT '',
    metrics_before    JSONB NOT NULL DEFAULT '{}',
    metrics_after     JSONB NOT NULL DEFAULT '{}',
    rollback_taken    BOOLEAN NOT NULL DEFAULT FALSE,
    lessons_learned   TEXT NOT NULL DEFAULT '',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_chaos_runs_tenant ON chaos_runs(tenant_id, started_at DESC);

CREATE TABLE IF NOT EXISTS chaos_approvals (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    experiment_id   UUID NOT NULL,
    experiment_name TEXT NOT NULL DEFAULT '',
    requested_by    TEXT NOT NULL DEFAULT '',
    justification   TEXT NOT NULL DEFAULT '',
    approvers       JSONB NOT NULL DEFAULT '[]',
    status          TEXT NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending','approved','rejected')),
    requested_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_chaos_approvals_tenant ON chaos_approvals(tenant_id, requested_at DESC);

-- Seed a starter experiment catalog for the default tenant (idempotent by name).
INSERT INTO chaos_experiments (tenant_id, name, category, description, severity_impact, target_type,
       estimated_duration_min, is_safe, hypothesis, blast_radius, rollback_procedure, steady_state_metrics, execution_steps)
SELECT '00000000-0000-0000-0000-000000000001',
       'EDRエージェント停止耐性テスト', 'endpoint',
       '一部エンドポイントでエージェントプロセスを意図的に停止し、検知の空白とウォッチドッグ復旧を検証する。',
       'medium', 'agent', 20, 'moderate_risk',
       'エージェント停止後60秒以内にウォッチドッグが再起動し、検知の空白は最小化される。',
       'テスト対象タグの付いた最大5台のエンドポイント',
       '["ウォッチドッグサービスを手動再起動","対象エージェントの稼働状態を確認","アラートを再有効化"]'::jsonb,
       '["オンライン エージェント数","アラート取り込みレート","ハートビート遅延"]'::jsonb,
       '["対象エンドポイントを選定(最大5台)","edr-agent プロセスを停止","検知空白時間を計測","ウォッチドッグ復旧を確認"]'::jsonb
WHERE NOT EXISTS (SELECT 1 FROM chaos_experiments WHERE tenant_id='00000000-0000-0000-0000-000000000001' AND name='EDRエージェント停止耐性テスト');

INSERT INTO chaos_experiments (tenant_id, name, category, description, severity_impact, target_type,
       estimated_duration_min, is_safe, hypothesis, blast_radius, rollback_procedure, steady_state_metrics, execution_steps)
SELECT '00000000-0000-0000-0000-000000000001',
       'NATS イベントストリーム遅延注入', 'network',
       'メッセージブローカーに人工的な遅延を注入し、イベント取り込みパイプラインの劣化耐性を検証する。',
       'high', 'network', 15, 'high_risk',
       '遅延注入下でもイベントはバッファされ、復旧後に欠損なく排出される。',
       '検証環境のイベント取り込みパイプライン全体',
       '["遅延注入ルールを削除","NATS 接続を再確立","バッファ排出を確認"]'::jsonb,
       '["イベント取り込みレート","エンドツーエンド遅延","バッファ滞留数"]'::jsonb,
       '["遅延注入を構成(例: +500ms)","取り込みレートとバッファを監視","復旧後の欠損有無を検証"]'::jsonb
WHERE NOT EXISTS (SELECT 1 FROM chaos_experiments WHERE tenant_id='00000000-0000-0000-0000-000000000001' AND name='NATS イベントストリーム遅延注入');

INSERT INTO chaos_experiments (tenant_id, name, category, description, severity_impact, target_type,
       estimated_duration_min, is_safe, hypothesis, blast_radius, rollback_procedure, steady_state_metrics, execution_steps)
SELECT '00000000-0000-0000-0000-000000000001',
       '認証サービス瞬断テスト', 'auth',
       '認証サービスを短時間停止し、トークン検証のフェイルセーフ挙動を検証する。',
       'medium', 'auth_service', 10, 'moderate_risk',
       '認証瞬断中も既存セッションは維持され、新規ログインのみが適切に失敗する。',
       'ログインおよびトークン更新エンドポイント',
       '["認証サービスを再起動","ヘルスチェックを確認","ログイン可否を検証"]'::jsonb,
       '["ログイン成功率","トークン検証レイテンシ","5xx エラー率"]'::jsonb,
       '["認証サービスを停止","既存セッションの継続性を確認","新規ログイン挙動を観察","サービスを復旧"]'::jsonb
WHERE NOT EXISTS (SELECT 1 FROM chaos_experiments WHERE tenant_id='00000000-0000-0000-0000-000000000001' AND name='認証サービス瞬断テスト');
