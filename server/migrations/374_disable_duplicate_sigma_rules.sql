-- 374: builtin と重複する DB ルールを無効化して二重計上を解消する
--
-- 背景 ─ 検知は2プロセスに分かれている:
--   server-api    AlertPipeline  → sigma_builtins.go の builtin ルール  → "[Sigma] ..."
--   server-detect Engine         → rules テーブルの DB ルール          → "[SIGMA] ..."
-- 両者は同じ NATS イベントを購読するため、実質同一のセレクタが両方に存在すると
-- 1つの事象が2件のアラートになる。良性フリートのみの FP ソーク (20台/1.67ホスト日)
-- では、この二重計上が11ペア・約60件 ─ 全445件の約13% ─ を占めていた。
--
-- 本 migration は「セレクタが実質同一で、builtin 側が DB 側を包含する」ことを
-- 個別に確認できた3件だけを無効化する。検知能力は落ちない。
-- 名前が似ているだけのペアは対象外 (下記「対象外」節)。
--
-- どちらを残すかの根拠: AlertPipeline は追いつき済で稼働する一方、detection-engine は
-- 慢性的に consumer ラグを抱える (docs/検知ルールの二重管理とデプロイ.md)。同じ検知なら
-- 即応する builtin 側を残す方が MTTD が短い。
--
-- curate との関係: CurateService.RunRound / ReconcileQuarantined はいずれも
-- source='sigmahq' の行しか UPDATE しない。ここで無効化するのは migration 由来の行
-- なので、次の curate ラウンドで再有効化されることはない。

-- ① curl/wget Download to Temp Directory (Linux) / T1105
--    builtin「curl/wget による /tmp へのファイルダウンロード」(sigma_builtins.go) と
--    selection_tool / selection_dest / condition が逐語的に同一。英語版と日本語版の差しかない。
UPDATE rules
SET enabled = false, updated_at = now()
WHERE id = 'b2c3d4e5-0003-0003-0003-000000000103';

-- ② SSH Authorized Keys Modification / T1098.004
--    builtin「SSH authorized_keys への不審な書き込み」は TargetFilename|contains が
--    '.ssh/authorized_keys' で、DB 側の '/.ssh/authorized_keys' を包含する
--    (contains マッチのため先頭スラッシュ有無に関わらず両方に当たる)。
--    なお builtin にはもう1つ同名の process_creation ルールがあるが、そちらは
--    CommandLine 経由の別軸で重複ではない (FP ソークでも発火していない)。
UPDATE rules
SET enabled = false, updated_at = now()
WHERE id = 'a1b2c3d4-0007-0007-0007-000000000033';

-- ③ Lateral Movement via RDP (migration 014) / T1021.001
--    これは builtin との重複ではなく DB 内の重複。migration 019 の
--    「RDP Lateral Movement via xfreerdp or mstsc」が mstsc.exe + ' \v:' に加えて
--    xfreerdp.exe / rdesktop.exe も見るため、014 は 019 の真部分集合である。
--    014 は id を明示せず INSERT されており環境ごとに id が変わるため content で特定する。
UPDATE rules
SET enabled = false, updated_at = now()
WHERE content LIKE '%title: Lateral Movement via RDP%'
  AND content NOT LIKE '%xfreerdp%';

-- 対象外 (単純削除では検知が落ちるため、別途の統合が必要):
--   PsExec Lateral Movement (DB, migration 286) と PsExec Remote Execution (builtin)
--   両者は互いの真部分集合ではない。DB 側だけが psexec64.exe / paexec.exe を
--   Image|endswith で厳密に見る一方、builtin 側だけが Image|contains でリネーム済み
--   バイナリに当たる。片方を消すとどちらかの検知が落ちるので、統合してから片方を
--   落とすこと。
--
-- 対象外 (curate 由来のため migration では制御できない):
--   Container Administration Command / Container Image Build on Host /
--   Container and Orchestration Discovery / Domain Account Discovery /
--   Domain Group Discovery / Network Share Discovery / Remote System Discovery /
--   WinRM Lateral Movement
--   これらは source='sigmahq' として同期された行で、FP ソークでは builtin と
--   二重計上していた。curate 側に「builtin が既にカバーする technique × logsource は
--   有効化しない」ゲートを設けるのが構造的な解決になる。
