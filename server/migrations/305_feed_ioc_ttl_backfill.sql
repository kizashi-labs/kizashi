-- 305: フィード由来 IOC にローリング有効期限(TTL)を後付けする。
-- これまでフィード IOC は expires_at 未設定で永久に蓄積し、古い攻撃IP(再割当で
-- 正規サービス化)が残り続けて時間とともに FP 源になっていた。feed_scheduler の
-- upsertIOC が今後 expires_at = NOW()+30日 をローリング付与するのに合わせ、既存
-- IOC も last_seen ベースで初期化する。
--
-- last_seen + 30日 を有効期限にするため、30日以上フィードに現れていない(=既に
-- ドロップした)古い IOC は過去日付になり、次回スイープで自動失効する。鮮度内の
-- IOC は有効のまま。手動追加(source_feed 空/manual)と STIX(独自 valid_until を
-- 持つ)は対象外。
UPDATE ioc_entries
   SET expires_at = COALESCE(last_seen, updated_at, created_at) + INTERVAL '30 days'
 WHERE expires_at IS NULL
   AND source_feed IS NOT NULL
   AND source_feed NOT IN ('', 'manual', 'stix-import');
