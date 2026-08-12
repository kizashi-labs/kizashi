-- 357: 集約条件を持つ Sigma ルールを評価可能な形に是正する。
--
-- sigma-go v0.6.6 の評価器は集約条件(`... | count() > N`)を実装しておらず、
-- 一致イベント到達時に nil 参照 panic を起こす。検知サーバのルール評価経路には
-- recover を追加した(多層防御)が、そもそも panic するルールを出荷し続ける理由はない。
-- これらのルールはこれまで別の不具合(sigma-go の timeframe パースバグ)によって
-- 偶然コンパイル前に落ちており、その結果 panic が表面化していなかっただけである。
--
-- migration 019 の定義も同内容に修正済み(新規構築時のため)。この migration は
-- 既存 DB を同じ状態へ収束させる。
--
-- 1) Ransomware File Extension Modification
--    集約を外して単発一致にする。対象拡張子(.locked/.WNCRY/.locky 等)は十分に特異で、
--    1件でも高信頼な指標。「短時間に大量」というレートの側面は、ランタイムの
--    ファイルバースト検知(FileBurstScorer, T1486)が担う。
UPDATE rules
SET content = replace(content, 'condition: selection | count() > 10', 'condition: selection')
WHERE id = 'a1b2c3d4-0009-0009-0009-000000000040'
  AND content LIKE '%count() > 10%';

-- 2) High-Volume DNS Queries Indicating DGA
--    集約を外すと「12文字以上の英数字ドメイン」全てに一致し、CDN 等で誤検知源になる。
--    同等の検知はランタイムの DNSTunnelAggregator と AnalyzeDGA が担っているため、
--    コンパイル可能な形に是正したうえで既定 disabled とする(チューニング後に有効化可)。
UPDATE rules
SET content = replace(content, 'condition: selection | count() by SourceIp > 50', 'condition: selection'),
    enabled = false
WHERE id = 'a1b2c3d4-0008-0008-0008-000000000037'
  AND content LIKE '%count() by SourceIp%';
