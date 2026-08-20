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

-- 330: dual-use ルールの環境依存チューニング用「オプトイン」抑制テンプレート。
--
-- 2026-07-13 の FP 調査で、Container Administration Command Execution(T1609,
-- docker/kubectl/podman exec)は良性(devops 運用)と悪性(侵害後のコンテナ横移動)が
-- コマンドラインで区別不能な純粋 dual-use と判明。ルール自体は本番ホストでは有効な
-- シグナルなので残すが、コンテナ/CI/ビルド専用フリートでは純ノイズになる。
--
-- ライブ検知の SuppressionMatcher は rule_name × hostname_regex で
-- アラートを抑制できる(hostname_regex の実装は 2026-08-18。上の訂正を参照)。本 migration は
-- その「環境スコープ抑制」の**オプトイン雛形**を seed する:
--   - is_active=FALSE(既定で無効)。運用者が hostname_regex を自組織のフリート命名に
--     合わせて調整し、is_active=TRUE にして初めて有効化される(誤って全ホスト抑制しない)。
--   - conditions は SuppressionMatcher が読む object 形 {rule_name, hostname_regex}。
--     rule_name でルールを、hostname_regex でホスト群を限定(prod ホストは対象外)。
-- 冪等: 固定 UUID + ON CONFLICT DO NOTHING。運用手順=docs/ops/検知ルールの環境依存チューニング.md。

INSERT INTO suppression_rules (id, name, description, conditions, is_active, expires_at)
VALUES (
  'd0a1c0de-0330-0001-0001-000000000001',
  '[テンプレート] Container Administration をコンテナ/CIフリートで抑制',
  'dual-use の T1609(docker/kubectl exec)を、コンテナ/CI/ビルド専用ホストでのみ抑制する雛形。既定で無効。hostname_regex を自組織のホスト命名に合わせて調整し is_active=TRUE で有効化すること。prod ホストでは引き続き発火させる。',
  jsonb_build_object(
    'rule_name', 'Container Administration',
    'hostname_regex', '(?i)^(k8s-node-|kube-|ci-runner-|.*-build-|docker-host-|containerd-)'
  ),
  FALSE,
  NULL
) ON CONFLICT (id) DO NOTHING;
