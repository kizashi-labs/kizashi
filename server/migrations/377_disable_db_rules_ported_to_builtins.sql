-- 377: builtin へ移設した DB ルールを無効化して二重評価を解消する
--
-- 背景 ─ P4-6 (このPR) で server-api の AlertPipeline も `rules` テーブルを
-- 読むようになった。狙いは「DB ルールがどちらの経路でも実質リアルタイム未発火」
-- という状態の解消だったが、副作用として **同じ行が2プロセスで評価される**:
--
--   server-api    AlertPipeline → "[Sigma] X"
--   server-detect RuleEngine    → "[SIGMA] X"
--
-- 1イベントが2行になる。dedup (internal/dedup) は両者を統合するものの、
-- 統合は行を status='resolved' にするだけで削除しないため、行数を数える
-- FP ソークのゲートには二重計上がそのまま出る。実測 (20台/1.67ホスト日、
-- 同一 seed): main 単体 403件 → 本PR 499件、+96。
-- 「行数」と「アナリストが見る件数」が別物である件は
-- docs/ops/FPソーク運用.md §4 に書いた。
--
-- ★ main の 374 が採った「builtin と重複する DB ルールを消す」方針は、
--   ここでは**そのままでは使えなかった**。ゲートが挙げた7件を1件ずつ
--   突き合わせた結果、builtin 側が DB 側を包含するペアは1つも無い:
--
--     WMI Remote Command Execution
--       builtin "Remote WMI Process Creation via wmic" は
--       wmic AND /node: AND "process call create" の3条件 AND。
--       DB 側は /node: 単独でも当たり、さらに WmiPrvSE 子プロセスも見る。
--       → builtin は DB の真部分集合。消すと検知が落ちる。
--     Container Administration Command (DB) / Container Image Build on Host (DB)
--       builtin は Image|endswith でバイナリを固定するが、DB 側は
--       コマンドライン上の文字列だけを見る。crictl と、ラッパ経由の
--       呼び出し (sudo docker exec / sudo docker build) を builtin は取り逃す。
--       → 互いに真部分集合ではない。374 が PsExec を対象外にしたのと同じ形。
--     疑わしいPowerShell実行 / Suspicious chmod of Executable in /tmp /
--     Script Execution from World-Writable Directory (Linux) /
--     Linux Shell Init File Modification (FIM)
--       → 対応する builtin がそもそも存在しない。
--
-- そこで「消す前に移す」。sigma_builtins.go に7件分のセレクタを**逐語的に**
-- 移設したうえで、ここで DB 行を落とす。移設の内訳:
--
--   Container 2件  既存 builtin に cmdline_only 分岐を追加して包含関係を成立させた
--   残り5件        builtin として新規追加 (セレクタは DB 行と同一)
--
-- したがって検知範囲は変わらない。変わるのは評価するプロセスだけで、
-- 移設後は api が builtin として1回評価し、detect はこの migration で
-- 無効化された行を読まないため発火しない (2N → N)。
-- 回帰は internal/detection/db_rule_builtin_port_test.go が押さえる
-- ——「無効化した行のセレクタに当たるイベントが、builtin でも必ず当たる」
-- ことを行ごとに確認する。builtin を削ったり狭めたりすると赤くなる。
--
-- どちらを残すかの根拠は 374 と同じ: AlertPipeline は追いつき済で稼働する一方、
-- detection-engine は慢性的に consumer ラグを抱える
-- (docs/検知ルールの二重管理とデプロイ.md)。同じ検知なら即応する api 側を残す。
--
-- curate との関係: CurateService.RunRound / ReconcileQuarantined は
-- source='sigmahq' の行しか UPDATE しない。ここで無効化するのは migration 由来
-- (003 / 014 / 019 / 295 / 311 / 322) の行なので、次の curate ラウンドで
-- 再有効化されることはない。

UPDATE rules SET enabled = false, updated_at = now()
WHERE name = 'WMI Remote Command Execution';

UPDATE rules SET enabled = false, updated_at = now()
WHERE name = '疑わしいPowerShell実行';

UPDATE rules SET enabled = false, updated_at = now()
WHERE name = 'Suspicious chmod of Executable in /tmp';

UPDATE rules SET enabled = false, updated_at = now()
WHERE name = 'Script Execution from World-Writable Directory (Linux)';

UPDATE rules SET enabled = false, updated_at = now()
WHERE name = 'Linux Shell Init File Modification (FIM)';

UPDATE rules SET enabled = false, updated_at = now()
WHERE name = 'Container Image Build on Host (DB)';

UPDATE rules SET enabled = false, updated_at = now()
WHERE name = 'Container Administration Command (DB)';
