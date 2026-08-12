-- Tier-1 AI トリアージの判定監査テーブル。
-- AITriageScheduler が新規アラートごとに「脅威インテリ文脈付与 → Claude 分析
-- → 構造化 tier-1 判定」を行い、その結果(分類/推奨アクション/根拠/自動適用
-- 有無)と判定の根拠になった intel シグナルをここに1行記録する。
-- ai_usage_logs は API 呼び出しメタデータ(モデル/レイテンシ)専用で判定内容は
-- 持たないため、SOC の説明責任・精度検証用に判定そのものを別途永続化する。
CREATE TABLE IF NOT EXISTS tier1_triage_decisions (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id           UUID NOT NULL,
    classification     TEXT NOT NULL,   -- true_positive|false_positive|benign|needs_analyst
    action             TEXT NOT NULL,   -- auto_close|escalate|assign|monitor
    confidence         DOUBLE PRECISION NOT NULL DEFAULT 0,
    priority           INT NOT NULL DEFAULT 3,   -- 1(最高)..4(最低)
    auto_applied       BOOLEAN NOT NULL DEFAULT FALSE,
    -- 判定根拠になった脅威インテリシグナル
    ioc_match          BOOLEAN NOT NULL DEFAULT FALSE,
    max_ioc_confidence INT,
    ioc_sources        TEXT[] DEFAULT '{}',
    related_alerts_24h INT,
    reasoning          TEXT,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_tier1_decisions_alert   ON tier1_triage_decisions(alert_id);
CREATE INDEX IF NOT EXISTS idx_tier1_decisions_action  ON tier1_triage_decisions(action);
CREATE INDEX IF NOT EXISTS idx_tier1_decisions_created ON tier1_triage_decisions(created_at DESC);
