-- 310: alerts / events の重複インデックス削除(書き込み増幅の低減)。
--
-- 2大書き込みテーブル alerts(実測576K行)/events は索引が過剰で、複数の
-- 「完全重複」(同一カラム・同一順序・述語なし)が存在していた。重複索引は
-- クエリプランには一切寄与せず(同一の索引が残るため)、INSERT/UPDATE のたびに
-- 全索引を更新する書き込みコストとストレージだけを増やす。ETW/eBPF のバースト
-- や継続的なアラート生成で write-hot なこれらのテーブルでは無視できない。
--
-- 各ペアで機能的に同一の索引を1つ残し、重複を削除する。DROP INDEX IF EXISTS で
-- 冪等。残す索引はクエリを完全に代替するためプラン変更なし。
--
-- alerts(残す ← 削除):
--   alerts_created_at_idx            ← idx_alerts_created_at            (created_at DESC)
--   alerts_agent_id_created_at_idx   ← idx_alerts_agent_id_created      (agent_id, created_at DESC)
--   alerts_agent_id_created_at_idx   ← idx_alerts_agent_created         (agent_id, created_at DESC)
-- events(残す ← 削除):
--   events_time_idx                  ← idx_events_time                  (time DESC)
--   events_agent_id_time_idx         ← idx_events_agent_time            (agent_id, time DESC)
--   events_event_type_time_idx       ← idx_events_type_time             (event_type, time DESC)

DROP INDEX IF EXISTS idx_alerts_created_at;
DROP INDEX IF EXISTS idx_alerts_agent_id_created;
DROP INDEX IF EXISTS idx_alerts_agent_created;

DROP INDEX IF EXISTS idx_events_time;
DROP INDEX IF EXISTS idx_events_agent_time;
DROP INDEX IF EXISTS idx_events_type_time;
