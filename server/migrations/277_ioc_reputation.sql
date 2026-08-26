-- P4 脅威インテリ: フィード取込IOCの ioc_type 列分断を根治し、多ソース・
-- レピュテーション(confidence/source_count/sources)を追加する。
--
-- 背景: FeedScheduler の INSERT は type だけを設定し ioc_type を NULL のままにして
-- いた(203 のバックフィルは一度きりで、その後の取込が全て NULL)。DB ポーリング型
-- マッチャ(scheduler/ioc_matcher.go)は ioc_type を読むため、フィード取込IOC(実測
-- 23,379件 全件 ioc_type=NULL)を取りこぼしていた。根本修正は feed_scheduler の
-- INSERT 側(ioc_type を type と同時に設定)。本 migration は既存 NULL の再バックフィルと
-- レピュテーション列追加。

-- 1) 既存 NULL を type から再バックフィル。
UPDATE ioc_entries SET ioc_type = type WHERE ioc_type IS NULL AND type IS NOT NULL;

-- 2) 多ソース・レピュテーション列。同一IOCが複数フィードに一致するほど confidence が
--    上がる(多ソース合意)。severity(深刻度)とは別軸の「どれだけ信頼できる指標か」。
ALTER TABLE ioc_entries
    ADD COLUMN IF NOT EXISTS confidence   SMALLINT NOT NULL DEFAULT 50,
    ADD COLUMN IF NOT EXISTS source_count SMALLINT NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS sources      TEXT[]   NOT NULL DEFAULT '{}';

CREATE INDEX IF NOT EXISTS idx_ioc_confidence ON ioc_entries(confidence DESC);
