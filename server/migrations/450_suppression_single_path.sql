-- 450: 抑制ルールの入れ物を1つに寄せる（移送）。
--
-- ── 何があったか ──────────────────────────────────────────────────────────
--
-- 抑制ルールの UI が **3つ**あり、**2つは保存できて絶対に効きません**でした。
--
--   A  /api/v1/suppressions             suppression_rules (object 形式)
--      画面 app/suppressions            **実働**。AlertPipeline の
--                                       SuppressionMatcher と server-detect が適用する
--
--   B  /api/v1/admin/suppression-rules  alert_suppression_rules
--      画面 admin/suppression-rules     **このテーブルを読む検知コードが1行も無い**。
--                                       画面の suppressed_count は 0 のままで、これは
--                                       「何にも一致しなかった」と読めるが、実際は
--                                       「一度も参照されていない」
--
--   C  /api/v1/admin/suppression/rules  suppression_rules (**array 形式**)
--      画面 admin/alert-suppression     internal/suppression.Engine。ShouldSuppress が
--                                       本番の検知経路から呼ばれない。さらに悪いことに
--                                       **A と同じ列に非互換な形式を書く** —— A の
--                                       ローダは conditions->>'rule_name' を読むので
--                                       配列からは何も取れず「条件ゼロ＝catch-all」と
--                                       判定して適用を拒み、逆に C のローダは A の
--                                       オブジェクトを parse できず毎回警告を出す
--
-- B と C を撤去して A に一本化する。この migration はその**データ移送**で、
-- コード側の削除は同じ PR で行う。
--
-- ── なぜ全部 is_active=FALSE で入れるか ──────────────────────────────────
--
-- **移送した瞬間に効き始めさせない。**
--
-- これらのルールは今まで一度も適用されていない。担当者から見ると「作ったのに
-- 効かない」状態が続いていたはずで、`suppression_matcher.go` が警告している
-- とおり、**効かない前提で条件を広げる調整**が積み上がっている可能性がある。
-- そのまま有効な状態で移送すると、本当にアラートが消え始める。抑制で消えた
-- アラートは、攻撃されていないことと外形が同じで、**後から取り戻せない**。
--
-- なので移送は「無効なルールとして持ち込む」だけにする。運用者が内容を見て
-- 有効化して初めて効く。挙動は移送の前後で変わらない。
--
-- 冪等: 同名の行が suppression_rules に既にあれば入れない。

-- ── B: alert_suppression_rules → suppression_rules ───────────────────────
--
-- 語彙の対応:
--   match_field='title' / 'rule_name'  → conditions.rule_name (部分一致)
--   match_field='hostname'             → conditions.hostname  (部分一致)
--   agent_id                           → conditions.agent_id  (完全一致)
--   severity_max (10 未満のときだけ)   → conditions.severity_max
--
-- **写せない match_field は捨てずに description に原文を残す。** 条件が空の
-- まま持ち込まれた行は catch-all になるが、is_active=FALSE なのでロードされず、
-- 仮に有効化されても ClassifySuppression が適用を拒む（二重の防御）。
INSERT INTO suppression_rules
  (name, description, conditions, duration_h, is_active, enabled, expires_at, hit_count, created_by, created_at)
SELECT
  a.name,
  TRIM(BOTH E'\n' FROM
    COALESCE(NULLIF(a.description, ''), '') ||
    E'\n[移送] 旧「アラート抑制ルール」画面 (/admin/suppression-rules) から移送。' ||
    E'\n元の条件: match_field=' || COALESCE(a.match_field, 'title') ||
    ' pattern=' || COALESCE(a.pattern, '') ||
    CASE WHEN a.agent_id IS NOT NULL THEN ' agent_id=' || a.agent_id::text ELSE '' END ||
    ' severity_max=' || a.severity_max ||
    CASE
      WHEN LOWER(COALESCE(a.match_field, 'title')) IN ('title', 'rule_name', 'hostname')
        THEN ''
      ELSE E'\n※ この match_field は移送先に対応する条件が無いため、条件に写せていません。'
    END ||
    E'\n※ 内容を確認してから有効化してください（移送時点では無効です）。'
  ),
  jsonb_strip_nulls(jsonb_build_object(
    'rule_name', CASE
      WHEN LOWER(COALESCE(a.match_field, 'title')) IN ('title', 'rule_name')
        THEN NULLIF(a.pattern, '') END,
    'hostname', CASE
      WHEN LOWER(COALESCE(a.match_field, 'title')) = 'hostname'
        THEN NULLIF(a.pattern, '') END,
    'agent_id', a.agent_id::text,
    -- severity_max=10 は alerts の上限そのもので何も除外しない（退化条件）。
    'severity_max', CASE WHEN a.severity_max BETWEEN 1 AND 9 THEN a.severity_max END
  )),
  24,
  FALSE,  -- is_active
  FALSE,  -- enabled（旗は2つあり、片方だけ書くともう片方の既定 TRUE が残る）
  a.expires_at,
  0,      -- hit_count。旧 suppressed_count は「一度も参照されていない」ので移送しない
  a.created_by,
  a.created_at
FROM alert_suppression_rules a
WHERE NOT EXISTS (
  SELECT 1 FROM suppression_rules s WHERE s.name = a.name
);

-- ── C: suppression_rules の array 形式を object 形式へ ────────────────────
--
-- internal/suppression.Engine が書いた行は conditions が
--   [{"field": "...", "operator": "...", "value": "..."}, ...]
-- という配列で、実働側のローダはこれを1つも読めない。読めるキーに写せる要素
-- だけを object に畳む。
--
-- operator は contains / eq のみ移す。実働側の一致の仕方は条件ごとに固定
-- （rule_name と hostname は部分一致、agent_id は完全一致）で、regex や
-- startswith を表現する手段が無い。**写せない条件を「近いから」と写すと、
-- 元より広く当たるルールになる。** 写せなかった分は description に残す。
UPDATE suppression_rules s
SET conditions = COALESCE(conv.obj, '{}'::jsonb),
    description = TRIM(BOTH E'\n' FROM
      COALESCE(s.description, '') ||
      E'\n[移送] 旧「アラート抑制」画面 (/admin/alert-suppression) の形式から変換。' ||
      E'\n元の条件: ' || s.conditions::text ||
      E'\n※ 内容を確認してから有効化してください（変換時点では無効です）。'),
    is_active = FALSE,
    enabled = FALSE,
    updated_at = NOW()
FROM (
  SELECT r.id,
         jsonb_strip_nulls(jsonb_object_agg(k.key, k.val) FILTER (WHERE k.key IS NOT NULL)) AS obj
  FROM suppression_rules r
  CROSS JOIN LATERAL jsonb_array_elements(r.conditions) AS e
  CROSS JOIN LATERAL (
    SELECT
      CASE LOWER(COALESCE(e->>'field', ''))
        WHEN 'rule_name' THEN 'rule_name'
        WHEN 'rulename'  THEN 'rule_name'
        WHEN 'hostname'  THEN 'hostname'
        WHEN 'agent_id'  THEN 'agent_id'
        WHEN 'mitre_technique' THEN 'mitre_technique'
      END AS key,
      to_jsonb(e->>'value') AS val
  ) AS k
  WHERE jsonb_typeof(r.conditions) = 'array'
    AND LOWER(COALESCE(e->>'operator', '')) IN ('contains', 'eq')
  GROUP BY r.id
) AS conv
WHERE s.id = conv.id;

-- 条件が1つも写せなかった配列の行（operator が regex だけ、など）も
-- object 形式に揃えておく。上の UPDATE は写せる要素が1つも無い行を
-- 拾わない（GROUP BY に現れない）ため。
UPDATE suppression_rules
SET conditions = '{}'::jsonb,
    description = TRIM(BOTH E'\n' FROM
      COALESCE(description, '') ||
      E'\n[移送] 旧「アラート抑制」画面 (/admin/alert-suppression) の形式から変換。' ||
      E'\n元の条件: ' || conditions::text ||
      E'\n※ 移送先に写せる条件がありませんでした。作り直してください（変換時点では無効です）。'),
    is_active = FALSE,
    enabled = FALSE,
    updated_at = NOW()
WHERE jsonb_typeof(conditions) = 'array';

-- ── 旧テーブルは残す（DROP しない） ──────────────────────────────────────
--
-- 移送が実環境で正しく行われたことを確認する前に消すと、確認する材料ごと
-- 無くなる。読み書きするコードはこの PR で全部消えるので、残っていても
-- 新しい行は増えない。DROP は移送結果を見てから別途判断する。
COMMENT ON TABLE alert_suppression_rules IS
  '廃止 (migration 450)。読む検知コードが一度も存在せず、この表の抑制ルールは適用されたことがない。行は suppression_rules へ無効な状態で移送済み。読み書きするコードは削除済みで、新しい行は増えない。DROP は移送結果を確認してから別途判断する。';
