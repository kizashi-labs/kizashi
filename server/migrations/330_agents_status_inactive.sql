-- 330: agents.status に 'inactive' を許可する。
--
-- 背景: DeadAgentCleanup スケジューラは 30 日以上オフラインのエージェントを
-- `UPDATE agents SET status = 'inactive'` で非アクティブ化するが、
-- migration 001 の CHECK 制約は ('online','offline','isolated','error') しか
-- 許可していないため、実行のたびに
--   new row for relation "agents" violates check constraint "agents_status_check"
-- (SQLSTATE 23514) で失敗していた (検証EC2 2026-07-30 のログで実測)。
-- = 長期間死んでいるエージェントが永久に 'offline' のまま残り、台数表示と
--   ライセンス上のアクティブ数が実態とずれる。
--
-- 是正: 制約に 'inactive' を追加する。フロントエンドの AgentStatusBadge にも
-- 'inactive' の表示を追加した (未知の status は 'offline' 表示にフォールバック
-- するため、この migration だけを先に当てても表示は壊れない)。
--
-- 冪等: DROP ... IF EXISTS の後に付け直すため、再実行しても安全。

ALTER TABLE agents DROP CONSTRAINT IF EXISTS agents_status_check;

ALTER TABLE agents ADD CONSTRAINT agents_status_check
    CHECK (status IN ('online', 'offline', 'isolated', 'error', 'inactive'));
