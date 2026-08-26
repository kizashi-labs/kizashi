-- AI 機能の Anthropic Claude API 呼び出し監査ログ。
--
-- 目的:
-- 1. APPI 第27条 (記録の作成等): 個人データの第三者提供記録の保管。
-- 2. 顧客 (特に Enterprise) からの「いつ誰がどれだけのデータを Claude に
--    送ったか説明できますか?」という質問への即答。
-- 3. 異常使用パターンの内部モニタリング (突発的なリクエスト急増 = アラート storm
--    かつ AI 自動分析、想定外コスト発生の早期検知)。
--
-- 重要 — このテーブルに記録しない情報:
-- - プロンプト本文 (sanitization の意義を打ち消すため)
-- - レスポンス本文
-- - マスクされたトークンの元値
-- - アラートペイロード本体
--
-- 記録するのはメタデータ (呼び出し時刻、function 名、文字数、トークン数、
-- レイテンシ、成功/失敗、参照先オブジェクト ID) のみ。

CREATE TABLE IF NOT EXISTS ai_usage_logs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    called_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- どの呼び出し点か (AnalyzeAlert / ExplainEvent / RecommendResponse /
    -- ChatQuery / GenerateDetectionRule など)
    function_name   TEXT NOT NULL,

    -- 使用された Claude モデル名 (claude-haiku-4-5-20251001 等)
    model           TEXT NOT NULL,

    -- 関連する元オブジェクト (alert UUID、incident UUID、rule ID 等)。
    -- Claude へ送られた本体ではなく source 識別子のみ — 復元には DB lookup が必要。
    related_id      TEXT,

    -- どの管理者の操作起点か (UI 経由の場合)。バックグラウンド呼び出し時 NULL。
    triggered_by    TEXT,

    -- 量的メタデータ
    tokens_masked   INTEGER NOT NULL DEFAULT 0,  -- sanitizer が置換したフィールド数
    prompt_chars    INTEGER NOT NULL DEFAULT 0,  -- 送信プロンプト文字数 (UTF-8)
    response_chars  INTEGER NOT NULL DEFAULT 0,  -- 受信レスポンス文字数 (UTF-8)
    latency_ms      INTEGER NOT NULL DEFAULT 0,

    -- 結果
    success         BOOLEAN NOT NULL DEFAULT FALSE,
    error_class     TEXT,  -- timeout / api_error / rate_limit / parse_error / unauthorized 等
    error_message   TEXT   -- error_class の詳細 (PII 含まない範囲)
);

CREATE INDEX IF NOT EXISTS idx_ai_usage_logs_called_at
    ON ai_usage_logs (called_at DESC);

CREATE INDEX IF NOT EXISTS idx_ai_usage_logs_function_name
    ON ai_usage_logs (function_name, called_at DESC);

CREATE INDEX IF NOT EXISTS idx_ai_usage_logs_related_id
    ON ai_usage_logs (related_id) WHERE related_id IS NOT NULL;

COMMENT ON TABLE ai_usage_logs IS
    'Audit log of Anthropic Claude API calls. Records metadata only — no prompt or response content, no masked-token values, no alert payload. APPI §27 third-party transfer record + Enterprise audit support. Added in v1.3.9 as step 4 of the AI compliance series.';

COMMENT ON COLUMN ai_usage_logs.tokens_masked IS
    'Number of sensitive field values the sanitizer (server/internal/aiassist/sanitizer.go) replaced before the prompt left the process. Higher = more PII shielded.';

COMMENT ON COLUMN ai_usage_logs.prompt_chars IS
    'UTF-8 character count of the outbound prompt. NOT a substitute for content review — useful for cost estimation and detecting abnormally large payloads.';
