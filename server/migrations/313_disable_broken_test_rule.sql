-- 313: 壊れたテスト残骸ルール "Test Custom Rule" を無効化する。
--
-- 2026-07-08 の死蔵ルール調査（本番 detection の `compiled=2077 failed=8`）で、
-- コンパイル失敗8件のうち7件は sigma-go 非対応の `all of <prefix>*` condition が原因で、
-- condition 前処理（expandAllOfWildcards, rule_engine.go）で復活させた。
-- 残る1件 "Test Custom Rule" はインデント不正の YAML（`title:` 直後の行が誤ネスト）で、
-- `Image|endswith: /test` / `status: test` という実検知価値の無いテスト投入残骸。
-- パースが必ず失敗し `enabled=t` でも評価されない＝死蔵。無効化して load ログを failed=0 に
-- そろえ、以後 `failed>0` が「本物の新規異常」を意味するようにする（可観測性の基準化）。
-- 冪等: 既に無効なら何もしない。削除でなく無効化（履歴保全・可逆）。

UPDATE rules
SET enabled = FALSE, updated_at = NOW()
WHERE name = 'Test Custom Rule'
  AND type = 'sigma'
  AND enabled = TRUE;
