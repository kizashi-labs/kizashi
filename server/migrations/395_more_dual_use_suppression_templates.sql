-- ── 2026-08-18 訂正 ────────────────────────────────────────────────────────
-- **この migration を書いた時点で hostname_regex を読むコードはありませんでした。**
-- 抑制ルールの読み手 (internal/detection/suppression_loader.go) が読むのは
-- conditions->>'hostname'（部分一致）だけで、hostname_regex はどの Go コードからも
-- 参照されていませんでした。つまりこのテンプレートは実際には
-- 「rule_name だけを条件に持つルール」として評価され、下の説明どおりに
-- is_active=TRUE にすると **ホストの絞り込みが一切効かず、prod を含む全ホストで
-- 該当ルールが抑制されます**。既定が is_active=FALSE だったため実害は出ていません。
--
-- 2026-08-18 に hostname_regex を実装したので、以下の記述はそのまま正しくなりました
-- （Go の RE2。コンパイルできない式は一致しない＝抑制しない方向に倒します）。
-- seed した conditions は変更不要です——キーはもともと正しく、読み手が無かった
-- だけなので、実装が追いついた時点で意図どおりに効きます。
-- ───────────────────────────────────────────────────────────────────────────

-- 331: dual-use ルールの環境依存チューニング雛形の追加(migration 330 の続き)。
--
-- 330 で Container Administration(T1609)のオプトイン抑制雛形を seed した。同様に
-- 「コマンドラインで良悪を分離できない」dual-use ルールを、正規運用が routine な
-- ホスト群でのみ抑制する雛形を追加する。いずれも既定で無効(is_active=FALSE)、
-- 運用者が hostname_regex を自組織のホスト命名に合わせて調整し有効化する。
-- rule_name で必ずルールを限定し、当該ホスト群上の他ルール(例: Mimikatz)は残す。
-- 手順=docs/ops/検知ルールの環境依存チューニング.md。冪等: 固定 UUID + ON CONFLICT DO NOTHING。
--
-- 注: PsExec/At.exe はイベントが「実行先(ターゲット)ホスト」で発火するため、
-- 「PsExec で routine に管理しているサーバ群」を hostname_regex に据えるのが基本。
-- BITS Job Abuse(T1197, medium)は正規アップデータが多い端末フリート向け。

INSERT INTO suppression_rules (id, name, description, conditions, is_active, expires_at)
VALUES
  (
    'd0a1c0de-0331-0001-0001-000000000001',
    '[テンプレート] PsExec を管理対象サーバ群で抑制',
    'dual-use の PsExec(Remote/Service/Lateral の各ルール名を rule_name="PsExec" で一括)を、PsExec で routine に管理しているサーバ/踏み台群でのみ抑制する雛形。既定で無効。hostname_regex を自組織の管理対象命名に合わせ、prod の機微ホストは外して有効化すること。',
    jsonb_build_object(
      'rule_name', 'PsExec',
      'hostname_regex', '(?i)^(mgmt-|jump-|bastion-|admin-)'
    ),
    FALSE,
    NULL
  ),
  (
    'd0a1c0de-0331-0002-0002-000000000002',
    '[テンプレート] At.exe レガシージョブを管理ホスト群で抑制',
    'dual-use の At.exe Legacy Job Scheduling を、レガシー管理タスクが routine なホスト群でのみ抑制する雛形。既定で無効。hostname_regex を調整し有効化すること。',
    jsonb_build_object(
      'rule_name', 'At.exe Legacy Job Scheduling',
      'hostname_regex', '(?i)^(mgmt-|jump-|legacy-)'
    ),
    FALSE,
    NULL
  ),
  (
    'd0a1c0de-0331-0003-0003-000000000003',
    '[テンプレート] BITS Job Abuse を端末フリートで抑制',
    'dual-use の BITS Job Abuse(T1197, medium。正規アップデータが BITS を多用)を、エンドユーザー端末フリートでのみ抑制する雛形。既定で無効。hostname_regex を端末命名に合わせて調整し有効化すること。サーバ側の BITS ステージングは残す。',
    jsonb_build_object(
      'rule_name', 'BITS Job Abuse',
      'hostname_regex', '(?i)(-ws-|-laptop-|-desktop-)|^(ws-|desktop-)'
    ),
    FALSE,
    NULL
  )
ON CONFLICT (id) DO NOTHING;
