-- Migration 371: 自動バックアップの記録先 backups テーブルを作る
--
-- scheduler/backup_scheduler.go は 24 時間ごとに pg_dump を回し、その結果を
-- backups テーブルに記録する設計になっている。しかしこのテーブルを作る
-- マイグレーションは存在しなかった。
--
-- runBackup は先頭で
--     SELECT EXISTS (SELECT 1 FROM pg_tables WHERE tablename = 'backups')
-- を確認し、無ければ Debug ログ 1 行だけ出して return する。テーブルが
-- 未作成である以上この分岐は常に成立し、**pg_dump は一度も実行されて
-- いない**。エラーも警告も出ないため、運用側からは毎日バックアップが
-- 取れているように見える。実際に必要になったとき初めて存在しないと分かる、
-- という最悪の壊れ方をしていた。
--
-- 同じテーブルを見ている経路がもう 1 つある。オンボーディングの
-- 「バックアップ設定済み」ステップ (api/handlers/onboarding_handler.go) も
-- tableExists("backups") で判定しているため、こちらも永久に未完了だった。
--
-- 列は backup_scheduler.go が実際に読み書きしている名前に合わせる。
CREATE TABLE IF NOT EXISTS backups (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    filename        TEXT NOT NULL,
    -- pending で挿入し、pg_dump と整合性検証を通れば completed、
    -- どちらかで落ちれば failed。この 3 語以外は書かれない。
    status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'completed', 'failed')),
    file_size_bytes BIGINT,
    error_message   TEXT,
    started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at     TIMESTAMPTZ,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- pruneOldBackups が started_at DESC で並べて 8 件目以降を消す。
CREATE INDEX IF NOT EXISTS idx_backups_started_at ON backups (started_at DESC);

-- スコアカード (RC.RP-2 / ISO A.17.1) とオンボーディングが
-- status で絞って直近 30 日を数える。
CREATE INDEX IF NOT EXISTS idx_backups_status_started_at ON backups (status, started_at DESC);
