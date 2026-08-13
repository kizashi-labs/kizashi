-- 381: builtin と重複する残りの builtin-parity 行を無効化する
--
-- 377 の続き。良性フリートでの A/B 実測 (20台/1.67ホスト日) で、technique 単位の
-- クロスエンジン統合が 88 件残っていた。内訳を追うと 3 つの別問題が混在しており、
-- そのうち「builtin と DB 行が同じ検知を 2 回出している」分がこの migration の対象:
--
--   T1021.006  WinRM Lateral Movement (DB)      ↔ WinRM Lateral Movement (winrs / …)
--   T1018      Remote System Discovery (DB)     ↔ Remote System and Domain Controller Discovery
--   T1087.002  Domain Account Discovery (DB)    ↔ Domain Account Discovery
--   T1069.002  Domain Group Discovery (DB)      ↔ Domain Group Discovery
--   T1135      Network Share Discovery (DB)     ↔ Network Share Discovery
--
-- ★ main の migration 374 はこの 5 件を「curate 由来のため migration では制御できない」
--   として対象外にしていたが、**それは事実誤認である**。実際に引くと 5 件とも
--   source='builtin-parity' で、migration 318 / 340 / 341 が INSERT した行だった:
--
--     edr_fpsoak=> SELECT name, source FROM rules WHERE name LIKE '%(DB)%';
--       Domain Account Discovery (DB)  | builtin-parity
--       Domain Group Discovery (DB)    | builtin-parity
--       Network Share Discovery (DB)   | builtin-parity
--       Remote System Discovery (DB)   | builtin-parity
--       WinRM Lateral Movement (DB)    | builtin-parity
--
--   sigmahq 同期由来ではないので、CurateService.RunRound / ReconcileQuarantined
--   (source='sigmahq' の行しか UPDATE しない) が再有効化することはない。
--   374 が挙げた除外理由は成立せず、377 と同じ手順で消せる。
--
-- 所有権を api に一本化した後は話が単純になる。detect は DB Sigma を評価しないので、
-- 残っていたのは「api が builtin と (DB) 行の両方を評価している」という 1 プロセス内の
-- 重複だった。DB 行を落とせば builtin だけが残る。
--
-- 包含関係は 1 件ずつ突き合わせた (方針ではなくルール単位の事実であるため):
--
--   Domain Group Discovery (DB)    セレクション名・条件・用語すべて builtin と逐語同一
--   Remote System Discovery (DB)   同上
--   Network Share Discovery (DB)   共通 3 枝が逐語同一。builtin は net_view_host と
--                                  snaffler を追加で持つ真包含
--   Domain Account Discovery (DB)  OR 構造どうしで builtin の用語集合が上位
--                                  (adsisearcher / DirectorySearcher を含む)
--   WinRM Lateral Movement (DB)    ❌ 包含していなかった。builtin は Image|contains で
--                                  winrs を見るが DB 側は CommandLine|contains なので、
--                                  ラッパ経由 (cmd /c winrs -r:host …) やリネーム済み
--                                  バイナリを builtin が取り逃す。
--                                  → sigma_builtins.go に winrs_cmdline 枝を追加して
--                                    吸収したうえで、ここで無効化する。
--
-- 回帰は internal/detection/db_rule_builtin_port_test.go が押さえる。
-- WinRM についてはラッパ経由のケースを代表イベントに選んである
-- ——当たりやすいケースで書くと、何も証明せずに緑になるため。

UPDATE rules SET enabled = false, updated_at = now()
WHERE name = 'WinRM Lateral Movement (DB)';

UPDATE rules SET enabled = false, updated_at = now()
WHERE name = 'Remote System Discovery (DB)';

UPDATE rules SET enabled = false, updated_at = now()
WHERE name = 'Domain Account Discovery (DB)';

UPDATE rules SET enabled = false, updated_at = now()
WHERE name = 'Domain Group Discovery (DB)';

UPDATE rules SET enabled = false, updated_at = now()
WHERE name = 'Network Share Discovery (DB)';
