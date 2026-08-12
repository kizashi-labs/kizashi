-- Migration 023: Seed well-known free OSINT threat intelligence feeds
-- All feeds are seeded as is_active = FALSE so operators can review and enable them
-- after confirming network access from the deployment environment.

INSERT INTO threat_feeds (name, url, feed_type, ioc_type, description, is_active, sync_interval_hours)
SELECT v.name, v.url, v.feed_type, v.ioc_type, v.description, v.is_active, v.sync_interval_hours
FROM (VALUES
  (
    'Feodo Tracker (C2 IPs)',
    'https://feodotracker.abuse.ch/downloads/ipblocklist.txt',
    'txt', 'ip',
    'abuse.ch - Emotet / QakBot / Dridex などのC2サーバーIPブロックリスト（6時間毎更新）',
    FALSE, 6
  ),
  (
    'URLhaus (マルウェア配布URL)',
    'https://urlhaus.abuse.ch/downloads/text/',
    'txt', 'url',
    'abuse.ch - マルウェアをホストしている活性URLのリスト（6時間毎更新）',
    FALSE, 6
  ),
  (
    'Blocklist.de (SSH攻撃IP)',
    'https://lists.blocklist.de/lists/ssh.txt',
    'txt', 'ip',
    'blocklist.de - SSHブルートフォース攻撃の送信元IPリスト（24時間毎更新）',
    FALSE, 24
  ),
  (
    'Blocklist.de (総合攻撃IP)',
    'https://lists.blocklist.de/lists/all.txt',
    'txt', 'ip',
    'blocklist.de - 全カテゴリの攻撃送信元IPリスト（24時間毎更新）',
    FALSE, 24
  ),
  (
    'OpenPhish (フィッシングURL)',
    'https://openphish.com/feed.txt',
    'txt', 'url',
    'OpenPhish - 活性フィッシングサイトのURLリスト（24時間毎更新）',
    FALSE, 24
  )
) AS v(name, url, feed_type, ioc_type, description, is_active, sync_interval_hours)
WHERE NOT EXISTS (
  SELECT 1 FROM threat_feeds WHERE threat_feeds.name = v.name
);
