-- 327: count() 集約ルールに明示的な timeframe を付与（FP/クラッシュ是正の一環）。
--
-- 2026-07-13 の condition 構文検証で、`selection | count() [by X] > N` を使う2ルール
-- （High-Volume DNS…DGA=T1568.002 / Ransomware File Extension Modification=T1486, 後者は
-- auto_isolate+auto_kill の critical）に timeframe が無いことが判明。
--   - RuleEngine(sigma-go) は count 実装が未配線だと集約評価で nil func を呼び PANIC する
--     （＝良性の単一 .enc/.locked ファイル改名や1回の DGA 状 DNS で検知ワーカーが落ちうる）。
--     → コード側で時間窓カウンタを配線して根治済（compileSigmaRule）。
--   - timeframe 未指定だと集約は「全時間の累積」となり窓がリセットされずメモリも増える。
--     コード既定（5分窓）で安全だが、閾値の意図をルール本文に明示する（特に critical/auto 応答ルール）。
-- 本 migration は既存DBの content に `timeframe: 5m` を前方付与。冪等（timeframe 既在ならスキップ）。
-- 019 のソースも同内容に修正済み。

-- DGA（037）: SourceIp 単位の高頻度 DNS。
UPDATE rules
SET content = regexp_replace(
      content,
      E'\\n(  condition: selection \\| count\\(\\) by SourceIp > 50)',
      E'\n  timeframe: 5m\n\\1'
    ),
    updated_at = NOW()
WHERE id = 'a1b2c3d4-0008-0008-0008-000000000037'
  AND content NOT LIKE '%timeframe:%';

-- Ransomware 拡張子改名（040, critical / auto_isolate / auto_kill）: 窓内の大量改名で発火。
UPDATE rules
SET content = regexp_replace(
      content,
      E'\\n(  condition: selection \\| count\\(\\) > 10)',
      E'\n  timeframe: 5m\n\\1'
    ),
    updated_at = NOW()
WHERE id = 'a1b2c3d4-0009-0009-0009-000000000040'
  AND content NOT LIKE '%timeframe:%';
