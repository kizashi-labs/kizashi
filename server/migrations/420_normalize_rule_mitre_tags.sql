-- 366: rules.mitre_tags に混入した生の Sigma タグを ATT&CK テクニックIDへ正規化する。
--
-- 発見(2026-08-03): 有効なルール25件が mitre_tags に "attack.t1059.004" や
-- "attack.execution" をそのまま保持していた。他のルールは "T1059.004" 形式である。
--
-- これは表記ゆれでは済まない。テクニック判定は文字列一致で行われるため、
-- "attack.t1059.004" は "T1059.004" と一致せず、**そのルールが発火しても
-- テクニックとして加点されない**。検知率の分子から丸ごと抜け落ちる。
-- 実際にアラートの mitre_technique に "attack.execution"（戦術名）が入っている
-- 行が観測されている。戦術はテクニックではないので、これも誤りである。
--
-- 投入経路について: SigmaHQ 同期 (internal/sync/sigmahq.go) は正しく正規化し、
-- テクニック以外のタグは捨てている。したがってこの25件は別経路（手動投入、
-- 旧バージョンの同期、または store.UpsertRule を直接呼ぶ箇所）由来である。
-- 本移行は既存行を直すもので、投入経路側の是正は別途必要。
--
-- 変換規則:
--   attack.t1059.004  → T1059.004   （テクニック。大文字化して attack. を除去）
--   attack.execution  → 削除         （戦術はテクニックではない。残すと
--                                      mitre_technique に戦術名が入る）
--   T1059.004         → そのまま     （既に正しい行は触らない）
--
-- 順序は保持する。sigma_builtins.go のコメントにあるとおり、最初の技術タグが
-- そのルールの主テクニックとして扱われるため、並び替えると意味が変わる。
-- 正規化の結果として重複した場合は最初の出現位置を残す。
WITH normalized AS (
  SELECT r.id,
         CASE
           WHEN lower(u.tag) ~ '^attack\.t[0-9]{4}(\.[0-9]{3})?$'
             THEN upper(substring(lower(u.tag) from 8))
           WHEN lower(u.tag) LIKE 'attack.%' THEN NULL
           ELSE u.tag
         END AS tag,
         u.ord
    FROM rules r, unnest(r.mitre_tags) WITH ORDINALITY AS u(tag, ord)
   WHERE EXISTS (SELECT 1 FROM unnest(r.mitre_tags) t WHERE lower(t) LIKE 'attack.%')
),
affected AS (SELECT DISTINCT id FROM normalized),
deduped AS (
  SELECT id, tag, min(ord) AS ord
    FROM normalized
   WHERE tag IS NOT NULL
   GROUP BY id, tag
),
rebuilt AS (
  SELECT id, array_agg(tag ORDER BY ord) AS tags FROM deduped GROUP BY id
)
UPDATE rules r
   SET mitre_tags = COALESCE(rb.tags, ARRAY[]::text[])
  FROM affected a
  LEFT JOIN rebuilt rb ON rb.id = a.id
 WHERE r.id = a.id;
