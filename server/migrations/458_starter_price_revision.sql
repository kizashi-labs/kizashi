-- 458_starter_price_revision.sql
--
-- 2026-08-25 経営承認: Starter プランの価格改定。
--   単価: ¥1,800 → ¥1,000 /エンドポイント/月
--   最小契約数: 50 → 30 EP（10台刻み、上限 199 のみ例外）
--   既存 Starter 顧客へは即時適用（差額は残存契約期間に応じてクレジット精算）
--
-- ライセンス上のエージェント上限（199）・機能割当は変更なし。
-- このマイグレーションは 199_license_plans_v2.sql が設定したテーブルコメント
-- （旧価格を含む）を現行価格に更新するだけで、データは変更しない。

COMMENT ON TABLE license_info IS
    'Platform license. Plans: lite (¥500/endpoint/mo, 5-45 endpoints), '
    'starter (¥1,000/endpoint/mo, 30-199 endpoints; revised 2026-08-25, was ¥1,800 / 50 min), '
    'professional (¥2,800/endpoint/mo, 200-999 endpoints), '
    'enterprise (custom pricing, 1000+ endpoints, unlimited users).';
