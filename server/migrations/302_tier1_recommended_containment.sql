-- tier-1 判定にエスカレーション時の封じ込め推奨(recommend-only)を記録する列を
-- 追加する。tier-1 は封じ込めを自動実行せず、アナリストが承認・実行するための
-- 推奨手順(影響ホスト隔離/一致IOCブロック/脅威ハンティング等)を判定と一緒に
-- 監査記録する。非エスカレーション判定では空配列。
ALTER TABLE tier1_triage_decisions
    ADD COLUMN IF NOT EXISTS recommended_containment TEXT[] NOT NULL DEFAULT '{}';
