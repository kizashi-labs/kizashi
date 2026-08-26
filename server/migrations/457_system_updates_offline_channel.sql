-- 457: system_updates / system_update_settings の channel に 'offline' を追加する
--
-- **#852 では 451 でした。公開版との収束で 457 へ動かしています。**
-- 451 は公開版が `451_agents_rls_drop_escape.sql`（RLS の 4 表 fail-closed 化）に
-- 使っており、**そちらは公開版で既に適用済み**です。migration は
-- `schema_migrations` にファイル名で記録されるので、適用済みの側を改名すると
-- 再実行されます —— 数の分からない公開版の利用者より、把握できている
-- こちら側を動かすほうが安全でした。
--
-- **この migration は再実行しても無害です**（下は DROP CONSTRAINT IF EXISTS →
-- ADD CONSTRAINT の形）。検証 EC2 では 451 の名前で適用済みなので、
-- 457 として一度だけ再実行されます。
--
-- オフラインバンドル（配布認証設計 第7段）で持ち込まれた更新は、GitHub Releases
-- でもレジストリでもなく「運用者が置いたバンドル」から来る。どこから来た更新かは
-- 画面にも失敗理由にも出したいので、channel で区別する。
--
-- ★ CHECK 制約は **置換ではなく追記**。このリポジトリでは events_event_type_check
-- の追記し忘れが3回再発しており、しかも制約違反は例外を握り潰されて静かに消える
-- ため、「機能が一度も動いていない」状態が長期間表面化しない。既存の 'stable' /
-- 'beta' を必ず残す。
--
-- 冪等: 制約を落としてから同名で作り直す。DROP は IF EXISTS で、まだ 236 が
-- 当たっていない環境でも失敗しない。

ALTER TABLE system_updates
    DROP CONSTRAINT IF EXISTS system_updates_channel_check;

ALTER TABLE system_updates
    ADD CONSTRAINT system_updates_channel_check
    CHECK (channel IN ('stable', 'beta', 'offline'));

ALTER TABLE system_update_settings
    DROP CONSTRAINT IF EXISTS system_update_settings_channel_check;

ALTER TABLE system_update_settings
    ADD CONSTRAINT system_update_settings_channel_check
    CHECK (channel IN ('stable', 'beta', 'offline'));
