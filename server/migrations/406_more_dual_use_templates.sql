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

-- 342: dual-use ツールルールの環境依存チューニング雛形の追加(330/331 の続き)。
--
-- 2026-07-20 の名前衝突/dual-use FP 調査で、単一用途だが正規利用もある2ルールを確認:
--   - Network Tunneling Tool Execution(T1572): ngrok/chisel/frp。ngrok は開発者が
--     ローカルサーバ公開に正規利用する(dual-use)。
--   - Data Exfiltration via Rclone(T1567): rclone copy/sync。正規のクラウド
--     バックアップに広く使われる(dual-use)。
-- いずれもコマンドラインで良悪を分離できないため、ルール本文は締めず(本番の
-- サーバでは有効なシグナル)、正規利用が routine なホスト群でのみ抑制する
-- オプトイン雛形を seed。既定で無効(is_active=FALSE)。手順=
-- docs/ops/検知ルールの環境依存チューニング.md。冪等: ON CONFLICT DO NOTHING。

INSERT INTO suppression_rules (id, name, description, conditions, is_active, expires_at)
VALUES
  (
    'd0a1c0de-0342-0001-0001-000000000001',
    '[テンプレート] Network Tunneling を開発/検証ホストで抑制',
    'dual-use の T1572(ngrok 等トンネルツール)を、ngrok を routine に使う開発/検証ホストでのみ抑制する雛形。既定で無効。hostname_regex を自組織の dev/test 命名に合わせ、prod は外して有効化すること。',
    jsonb_build_object(
      'rule_name', 'Network Tunneling',
      'hostname_regex', '(?i)(-dev-|-test-|-staging-)|^(dev-|test-)'
    ),
    FALSE,
    NULL
  ),
  (
    'd0a1c0de-0342-0002-0002-000000000002',
    '[テンプレート] Rclone をバックアップホストで抑制',
    'dual-use の T1567(rclone copy/sync)を、rclone を正規バックアップに使うホスト群でのみ抑制する雛形。既定で無効。hostname_regex をバックアップ/ジョブホスト命名に合わせて調整し有効化すること。',
    jsonb_build_object(
      'rule_name', 'Rclone',
      'hostname_regex', '(?i)(-backup-|-bkp-|-job-)|^(backup-|bkp-)'
    ),
    FALSE,
    NULL
  )
ON CONFLICT (id) DO NOTHING;
