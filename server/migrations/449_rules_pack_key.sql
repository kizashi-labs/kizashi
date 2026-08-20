-- 449_rules_pack_key.sql
--
-- ルールパックから読み込んだルールに、安定した識別子を持たせる。
--
-- 背景: 検知ルール 2,404 件は 96 本の migration に INSERT として直接埋め込まれて
-- おり、内容の更新には新しい migration を書くしかない。これは2つの問題を持つ:
--
--   1. 配布の単位が「マイグレーション＝スキーマ変更」と同じになっており、
--      検知コンテンツだけを別条件で配ることができない
--   2. 内容の差し替えが追記でしか行えず、どの migration がどのルールを
--      作ったのかを後から辿れない
--
-- pack_key は `<パック名>/<ルール名>` の形で、パック側の同一性を表す。
-- これがあると読み込みが冪等になり、同じパックを再読込しても重複しない。
--
-- name に一意制約を張らないのは、実DBに重複が既に存在するため(2026-08-19 時点で
-- 1組)。重複の整理は別の作業であり、パックの読み込みをその完了に依存させない。
--
-- 部分索引にしてあるので、パック由来でないルール(手書き・AI生成・curate 取込)は
-- 従来どおり pack_key = NULL のまま影響を受けない。

ALTER TABLE rules
    ADD COLUMN IF NOT EXISTS pack_key TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS rules_pack_key_uniq
    ON rules (pack_key)
    WHERE pack_key IS NOT NULL;

COMMENT ON COLUMN rules.pack_key IS
    'ルールパック内での識別子（<パック名>/<ルール名>）。パック由来でないルールは NULL';
