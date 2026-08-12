-- 324: マルチテナント RLS を FORCE 化(テナント分離ハードニング)。
--
-- 背景(2026-07 セキュリティ監査): agents/alerts/incidents は migration 027 で
-- RLS を ENABLE 済みだが、以下の理由でテナント分離が実効していなかった:
--   (1) アプリが DB スーパーユーザ(rolsuper/rolbypassrls)で接続 → RLS を無条件
--       素通り。★これは別途「非スーパーユーザ・アプリロールへの切替」で是正する
--       (docs/security/マルチテナント分離ハードニング.md 参照)。この migration
--       だけでは是正されない。
--   (2) RLS が FORCE でない → テーブル所有者(edr)も RLS を素通り。
--
-- この migration は (2) を是正する: FORCE ROW LEVEL SECURITY によりテーブル
-- 所有者も RLS の対象になる。(1) のロール切替と併せて初めてテナント分離が実効化
-- する(検証: 非スーパーユーザ・非所有者ロールで app.tenant_id を設定すると、
-- 非マッチテナントの行は 0 件になることをライブ DB で確認済み)。
--
-- 冪等: FORCE の設定は繰り返し実行しても安全。RLS ポリシーの
-- "app.tenant_id IS NULL OR ''" エスケープ節により、app.tenant_id を設定しない
-- バックグラウンドワーカ(検知エンジン/スケジューラ)や migration 自身は従来どおり
-- 全テナントにアクセスできる(意図された挙動)。

ALTER TABLE agents    FORCE ROW LEVEL SECURITY;
ALTER TABLE alerts    FORCE ROW LEVEL SECURITY;
ALTER TABLE incidents FORCE ROW LEVEL SECURITY;
