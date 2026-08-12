-- 374: PsExec ルールを builtin 側に統合し、DB 側を無効化する
--
-- migration 374 では PsExec のペアを「互いの真部分集合ではない」として対象外にした:
--
--   DB (mig 286)  Image|endswith  \psexec.exe \psexec64.exe \paexec.exe \psexesvc.exe
--                 CommandLine|contains  -accepteula / PSEXESVC
--   builtin       Image|contains  psexec.exe psexesvc.exe
--                 CommandLine|contains  accepteula
--
-- DB 側だけが psexec64.exe / paexec.exe を見て、builtin 側だけが contains により
-- リネーム済みバイナリ (svchost_update.exe 等) に当たる。片方を落とすとどちらかの
-- 検知が落ちるため、統合が先だった。
--
-- 同 PR で builtin 側に psexec64.exe と PSEXESVC を追加し、builtin が DB を完全に
-- 包含する状態にした。contains は endswith を包含するので (例: '\psexec64.exe' に
-- 当たる入力は 'psexec64.exe' にも当たる)、DB 側に固有の検知はもう残っていない。
--
-- paexec.exe は builtin 側に追加していない。既存の別ルール
-- "PsExec-Alternative Remote Execution Tool (PAExec/RemCom)" が Image|contains で
-- 既にカバーしているためで、両方に入れると paexec.exe の1実行が builtin 内で2件の
-- アラートになり、この migration が消そうとしている二重計上を別の場所で再現してしまう。
-- 「DB が発火する全ケースで builtin も発火する」ことと「paexec は別ルールだけが拾う」
-- ことは psexec_builtin_merge_test.go でイベント単位に検証している。
--
-- 二重計上の解消という目的は 373 と同じ。detection-engine は慢性的に consumer ラグを
-- 抱えるので、同じ検知なら追いつき済の AlertPipeline (builtin) 側を残す方が MTTD が短い。
--
-- migration 286 の YAML とそれを守る psexec_fp_test.go はそのまま残す。ルールを
-- 無効化しても content は履歴として有効で、`curl -s` 型の FP を再発させないという
-- 検証の意図は builtin 側に移した同等のテストが引き継いでいる。

UPDATE rules
SET enabled = false, updated_at = now()
WHERE id = 'a1b2c3d4-0001-0001-0001-000000000001';
