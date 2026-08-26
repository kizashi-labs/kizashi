-- 292: curate 衛生の是正と「quarantined ⟹ disabled」不変条件の恒久化。
--
-- 検証環境の rules で 2 種類の curate_state 不整合を発見した:
--
--   (A) curate_state='quarantined' なのに enabled=true が 3 件。
--       いずれも FP 監視(MonitorFP→Quarantine)が enabled=false にして隔離した後、
--       汎用トグル(RuleStore.Toggle)/編集(Update)経路が curate_state を無視して
--       enabled=true に戻したために生じた「隔離が効かず今も FP 発火」状態。
--       (例: "File and Directory Discovery - MacOS" が Linux テレメトリに誤マッチ)
--       → enabled=false に戻し、隔離を実効化する。
--
--   (B) curate_state='deferred' なのに enabled=true が 96 件。
--       deferred は「field 対応済みだが per-category cap 超過で次ラウンド待ち」
--       (278 の語彙・curate.go の権威定義)であり inert ではない。実際これらは
--       Linux Shell Pipe to Shell / Vim GTFOBin / PowerShell Cradles 等の実検知で、
--       一部は実テレメトリに発火中。有効化済みの実態に合わせ curate_state='enabled'
--       へ是正する(無効化はカバレッジ後退になるため行わない)。
--
-- 併せて、隔離を再有効化から構造的に守るため CHECK 制約で不変条件を恒久化する。
-- 制約追加は不整合行を是正した後でなければ失敗するため、順序は (A)(B) → 制約。

-- (A) quarantined なのに有効 → 無効化して隔離を実効化
UPDATE rules SET enabled = false, updated_at = NOW()
WHERE source = 'sigmahq' AND curate_state = 'quarantined' AND enabled = true;

-- (B) deferred なのに有効 → 実態(有効化済み)に合わせて curate_state を是正
UPDATE rules SET curate_state = 'enabled', curated_at = COALESCE(curated_at, NOW()), updated_at = NOW()
WHERE source = 'sigmahq' AND curate_state = 'deferred' AND enabled = true;

-- 不変条件: quarantined なルールは必ず無効。NULL(curate 非管理)や他 state は影響なし。
-- Toggle/Update/手動 SQL のどの経路からでも隔離が再有効化されるのを DB 層で拒否する。
ALTER TABLE rules DROP CONSTRAINT IF EXISTS rules_quarantine_disabled_check;
ALTER TABLE rules ADD CONSTRAINT rules_quarantine_disabled_check
    CHECK (curate_state IS DISTINCT FROM 'quarantined' OR enabled = false);
