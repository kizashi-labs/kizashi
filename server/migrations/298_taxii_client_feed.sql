-- TAXII 2.1 クライアント購読フィードを追加する。
-- source_format="taxii21" の threat_feeds 行は feed_scheduler が
-- internal/intel.TAXIIClient に委譲し、コレクションの Get Objects
-- エンドポイントを added_after(前回同期時刻)で増分 pull して STIX
-- Indicator を IOC として取り込む。
--
-- url          : コレクションのエンドポイント
--                (例 https://host/taxii2/api1/collections/<id>/ 。
--                 クライアントが末尾に objects/ を補完する)
-- api_key      : Bearer トークン。"user:pass" 形式なら HTTP Basic として送信
--                (Anomali Limo 系の guest:guest 等)
-- headers      : 非標準認証スキーム用の追加ヘッダ(例 OTX の X-OTX-API-KEY)
--
-- 雛形は is_active=FALSE でシードする。運用者が threat-feeds API / 管理 UI で
-- url と認証情報を設定し有効化することで購読が始まる。source_format をキーに
-- 冪等化(再適用しても重複INSERTしない)。認証・URL 未設定のまま有効化しても
-- 取得は 0 件で last_sync だけ進む(既存フィードと同じくタイトなリトライなし)。
INSERT INTO threat_feeds (name, url, feed_type, source_format, ioc_type, is_active, sync_interval_hours, description)
SELECT 'TAXII 2.1 Collection (example)',
       'https://taxii.example.org/taxii2/api1/collections/00000000-0000-0000-0000-000000000000/',
       'taxii', 'taxii21', 'mixed', FALSE, 6,
       'TAXII 2.1 collection subscription template — set url + api_key and enable to pull STIX indicators'
WHERE NOT EXISTS (
    SELECT 1 FROM threat_feeds WHERE source_format = 'taxii21'
);
