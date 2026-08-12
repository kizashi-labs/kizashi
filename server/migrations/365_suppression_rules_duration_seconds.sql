-- Migration 365: suppression_rules に duration_seconds を実際に追加する
--
-- 180_suppression_rules.sql は duration_seconds を含む定義で
-- CREATE TABLE IF NOT EXISTS していたが、suppression_rules は
-- 010_suppressions_incidents.sql が先に作っている。IF NOT EXISTS なので
-- 180 のテーブル定義はまるごと no-op になり、duration_seconds は
-- 一度も作られていなかった (180 が別行の ALTER で足した enabled だけが
-- 存在するのはそのため)。
--
-- 結果として internal/suppression/engine.go の 3 つのクエリが全滅していた:
--
--   LoadFromDB   SELECT ... COALESCE(duration_seconds,0) ...
--                → column does not exist。err は Debug に落として nil を返す
--                  実装なので、抑制ルールが 0 件のまま静かに起動していた
--   AddRule      INSERT INTO suppression_rules (..., duration_seconds, ...)
--   UpdateRule   UPDATE ... SET ..., duration_seconds=$5, ...
--
-- つまり抑制ルールは「保存もされず、読み込まれもしない」状態だった。
-- 既知の良性アラートを黙らせる仕組みが丸ごと機能していないため、
-- 誤検知がそのまま SOC のキューに出続けていたことになる。
--
-- 列を足して 180 の意図どおりにする。既存の duration_h (時間単位) は
-- 010 由来で NOT NULL DEFAULT 24 のため、INSERT が省略しても既定値で埋まる。
-- 秒精度を持つ duration_seconds を正とし、duration_h には触れない。
ALTER TABLE suppression_rules ADD COLUMN IF NOT EXISTS duration_seconds INTEGER DEFAULT 0;

-- 既存行は duration_h から移送する。0 のままだと「抑制期間なし」として
-- 解釈され、これまで登録されていたルールの意図が変わってしまう。
UPDATE suppression_rules
SET duration_seconds = COALESCE(duration_h, 0) * 3600
WHERE duration_seconds IS NULL OR duration_seconds = 0;
