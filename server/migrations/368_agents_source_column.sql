-- Migration 368: agents.source を追加する
--
-- Wazuh 取り込み (internal/api/handlers/ingest_handler.go) は
--
--     INSERT INTO agents (hostname, ip_addresses, os_type, status, last_seen, source)
--     VALUES (..., 'wazuh')
--
-- と書き、統計エンドポイントは
--
--     SELECT COUNT(*) FROM agents WHERE source = 'wazuh'
--
-- と読むが、agents に source 列は無かった。INSERT は
-- `column "source" of relation "agents" does not exist` で必ず失敗し、
-- Wazuh 経由で初めて見るホストはエージェントを作れず、そのアラートも
-- まるごと落ちていた (upsertAgent の失敗で 500)。
--
-- alerts 側は同じ用途の source 列を migration 270 で追加済みなので、
-- それに合わせる。既定は 'agent' — 本体エージェントが自分で登録した
-- ホストが圧倒的多数で、既存行はすべてそれに当たる。
--
-- タグ (agents.tags) に入れる案は取らない。tags は UpdateAgentMeta で
-- 利用者が編集でき、外されると出どころが分からなくなるため。
ALTER TABLE agents ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'agent';

-- 「Wazuh 由来のホスト数」を数える統計が主用途。件数が増えても
-- 全件走査にならないよう張る。
CREATE INDEX IF NOT EXISTS idx_agents_source ON agents (source);
