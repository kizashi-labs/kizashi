-- 330: dual-use ルールの環境依存チューニング用「オプトイン」抑制テンプレート。
--
-- 2026-07-13 の FP 調査で、Container Administration Command Execution(T1609,
-- docker/kubectl/podman exec)は良性(devops 運用)と悪性(侵害後のコンテナ横移動)が
-- コマンドラインで区別不能な純粋 dual-use と判明。ルール自体は本番ホストでは有効な
-- シグナルなので残すが、コンテナ/CI/ビルド専用フリートでは純ノイズになる。
--
-- ライブ検知(RuleEngine)の SuppressionMatcher は rule_name × hostname_regex で
-- アラートを抑制できる(hostname_regex は migration 同時期に追加)。本 migration は
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
