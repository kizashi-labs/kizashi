-- P4: abuse.ch ThreatFox フィードを追加する。
-- ThreatFox は1ファイルに ip:port / domain / url / hash を混在させる高鮮度の
-- IOC フィードで、feed_scheduler が threatfox_csv を internal/intel パーサ
-- (parseThreatFoxCSV, 行毎の ioc_type 列でタイプ判定) に委譲する。
--
-- abuse.ch はダウンロードを Auth-Key ヘッダでゲートするため、キー未設定だと
-- 取得は 0 件で last_sync だけ進む(migration 275 と同じ挙動=タイトなリトライ
-- ループなし)。運用者が threat-feeds API で api_key を追加すると取り込みが
-- 有効化される。source_format をキーに冪等化(再適用しても重複INSERTしない)。
INSERT INTO threat_feeds (name, url, feed_type, source_format, is_active, description)
SELECT 'abuse.ch ThreatFox',
       'https://threatfox.abuse.ch/export/csv/recent/',
       'composite', 'threatfox_csv', TRUE,
       'ThreatFox mixed IOC feed (ip/domain/url/hash) from abuse.ch'
WHERE NOT EXISTS (
    SELECT 1 FROM threat_feeds WHERE source_format = 'threatfox_csv'
);
