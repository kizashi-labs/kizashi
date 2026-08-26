-- Migration 373: ソフトウェアインベントリのスナップショットに中身を持たせる
--
-- 「昨日から何が入って何が消えたか」を出す機能が、構造的に
-- 「変化なし」しか答えられない状態だった。実測で確認した内訳は 3 つ。
--
-- (1) 差分計算が存在しないテーブルを読んでいた
--     api/handlers/software_diff_handler.go の ComputeDiff は
--     agent_software と agent_software_history を読む。どちらも
--     マイグレーションに存在しない。tableExists ガードの内側なので
--     エラーにもならず、current も prev も空のまま
--     added_count=0 / removed_count=0 を「結果」として保存していた。
--     実際のインベントリは endpoint_software (016) にある。
--
-- (2) スナップショットに中身が無い
--     software_inventory_snapshots は software_count しか持たない。
--     件数だけでは「何が」増えたかを復元できないので、仮に (1) を
--     直してもこのテーブルからは差分を作れない。
--
-- (3) スナップショットを書く経路が無い
--     store.SoftwareDiffStore.CreateSnapshot の呼び出し元は
--     カバレッジテストのみ。本番経路からは一度も呼ばれていない。
--     一方 SoftwareInventoryStore.UpsertBatch はエージェント報告のたびに
--     DELETE してから INSERT し直すため、**前日のインベントリは毎回破棄される**。
--     比較対象そのものが残らない。
--
-- ここでは (2) を直す。(1) と (3) はコード側で対応する。
ALTER TABLE software_inventory_snapshots
    ADD COLUMN IF NOT EXISTS software JSONB NOT NULL DEFAULT '[]'::jsonb;

-- 差分は (agent_id, diff_date) で 1 行であってほしい。ComputeDiff は
-- 再実行できる (UI のボタン) が、UNIQUE が無いため同じ日の行が積み上がり、
-- GetLatestDiff の ORDER BY diff_date DESC は同日行の中で順序が決まらない。
-- つまり再計算しても古い方が返る可能性がある。
--
-- 既存の重複は最新 (created_at が新しい方) を残して削除してから張る。
DELETE FROM software_inventory_diffs a
      USING software_inventory_diffs b
      WHERE a.agent_id = b.agent_id
        AND a.diff_date = b.diff_date
        AND (a.created_at < b.created_at
             OR (a.created_at = b.created_at AND a.id < b.id));

CREATE UNIQUE INDEX IF NOT EXISTS uq_sw_diffs_agent_date
    ON software_inventory_diffs (agent_id, diff_date);
