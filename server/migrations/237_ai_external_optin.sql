-- AI 機能のデータ外部送信に対するテナント opt-in。
--
-- AI 調査機能 (FeatureAIInvestigation) を有効化したテナントが、
-- アラート JSON を Anthropic Claude API へ送信することへ明示的に同意したかを表す。
-- デフォルト false: Pro/Enterprise プランで FeatureAIInvestigation を持っていても、
-- このフラグが true になるまで `aiassist.callClaude` 系の経路は HTTP 403 で拒否される。
--
-- 背景:
-- - 個人情報保護法 (APPI 2022 改正) 28 条: 個人データの第三国移転 (Anthropic = 米国)
--   には本人同意 + 移転先体制の情報提供が必要。
-- - FISC: 金融機関データの第三者クラウド転送制限。
-- - 顧客が「AI 機能契約しているが越境転送は嫌」というケースもあり、
--   それは「Ollama 等のローカル AI モデルに切替」が将来的な選択肢。
--   それまでは AI 機能 OFF にする逃げ道として opt-in を提供する。

ALTER TABLE license_info
    ADD COLUMN IF NOT EXISTS ai_external_optin BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN license_info.ai_external_optin IS
    'Tenant explicitly consents to sending alert payloads / chat history / rule generation prompts to Anthropic Claude API. Default false. Required true for any aiassist.callClaude path to execute (HTTP 403 otherwise). Toggled via PUT /api/v1/admin/license/ai-optin (admin only).';
