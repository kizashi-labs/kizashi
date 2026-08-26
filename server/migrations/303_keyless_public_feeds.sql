-- キー不要の公開悪性IPフィードを追加し、IOC 照合の母数を拡張する。
-- いずれも認証不要で取得でき(検証EC2から HTTP 200・実データ確認済み)、
-- FeedScheduler の汎用テキスト取込(importTextFeed, 行の先頭トークンを IP として
-- upsert)で処理される。source_format='custom' は汎用取込にルーティングされる。
--
-- Tor 出口ノードリスト等の「良性トラフィックを含みうる」リストは誤検知源に
-- なるため意図的に除外し、複数ブロックリストで観測された高信頼の悪性 IP のみを
-- 採用する。url をキーに冪等化。
INSERT INTO threat_feeds (name, url, feed_type, source_format, ioc_type, is_active, sync_interval_hours, description)
SELECT v.name, v.url, v.feed_type, v.source_format, v.ioc_type, v.is_active, v.sync_interval_hours, v.description
FROM (VALUES
    ('CINS Army List',
     'http://cinsscore.com/list/ci-badguys.txt',
     'txt', 'custom', 'ip', TRUE, 12,
     'CINS Army poor-reputation attacker IPs (keyless)'),
    ('IPsum Level 3',
     'https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt',
     'txt', 'custom', 'ip', TRUE, 24,
     'Aggregated malicious IPs seen on >=3 blocklists (keyless)')
) AS v(name, url, feed_type, source_format, ioc_type, is_active, sync_interval_hours, description)
WHERE NOT EXISTS (SELECT 1 FROM threat_feeds tf WHERE tf.url = v.url);

-- 既にシード済みだが眠っている(is_active=FALSE)キー不要フィードを有効化する。
UPDATE threat_feeds SET is_active = TRUE, updated_at = NOW()
WHERE is_active = FALSE
  AND url IN (
      'https://lists.blocklist.de/lists/all.txt'
  );
