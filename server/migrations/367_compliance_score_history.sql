-- Migration 367: 組織全体のコンプライアンススコア履歴を専用テーブルに分ける
--
-- compliance_scores には相容れない 2 つの設計が同居していた。
--
--   (1) エージェント単位の最新スコア
--       agent_id NOT NULL / UNIQUE(agent_id, framework) / store/compliance_scores.go
--   (2) 組織全体スコアの時系列履歴
--       scheduler/compliance_scorer.go が framework ごとに INSERT し、
--       calculated_at < NOW() - 30 days を削除して 30 日分を保持しようとする
--
-- (2) は agent_id を渡していなかったため NOT NULL 制約で毎回失敗し、
-- mitre / cis / nist / iso27001 の 4 フレームワークとも**一度も保存されて
-- いなかった**。エラーは slog.Error に出るだけで、スコアラー自体は
-- 動き続けるため「計算しているのに画面に出ない」状態になっていた。
--
-- 仮に agent_id を埋めても (2) は成立しない。UNIQUE(agent_id, framework)
-- がある限り同じ framework の 2 行目を入れられず、履歴が持てないため。
-- つまり列の追加漏れではなく、テーブルの用途が二重になっているのが原因。
--
-- 組織全体スコアを専用テーブルへ移す。compliance_scores は (1) 専用に戻る。
CREATE TABLE IF NOT EXISTS compliance_score_history (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    framework     TEXT NOT NULL,
    score         INTEGER NOT NULL,
    details       JSONB NOT NULL DEFAULT '{}',
    calculated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 「framework ごとの最新行」を引く読み出しが主用途なので、その並びで張る。
CREATE INDEX IF NOT EXISTS idx_compliance_score_history_framework_time
    ON compliance_score_history (framework, calculated_at DESC);

-- 30 日保持の削除が calculated_at 全体走査になるのを避ける。
CREATE INDEX IF NOT EXISTS idx_compliance_score_history_time
    ON compliance_score_history (calculated_at);
