-- 発火不能な日本語ルール2件を無効化し、自動隔離の対象から外す。
--
-- 対象は migration 003 が入れた次の2件で、どちらも英語版と同じ技法を狙った
-- 「重複」に見えていたが、実測すると重複ではなく **構造的に一度も発火できない**
-- 内容だった（実DBでの調査 = docs/results/live-20260818-jp-duplicate-rules-inert.md）。
--
--   1. シャドウコピー削除コマンド（ランサムウェア）  T1490   全期間 0 件
--   2. LSASSメモリダンプ（資格情報窃取）            T1003.001 全期間 0 件
--
-- 対する英語版は同じ日・同じホスト・同じ攻撃バッテリで発火している
-- （Shadow Copy Deletion via vssadmin or wmic = 5 件、LSASS Memory Dump via
-- Procdump = 1 件、いずれも 2026-07-18）。同じ入力に対して英語版だけが鳴ったので、
-- 環境や母集団の違いではない。
--
-- なぜ発火できないか。
--
-- (1) シャドウコピー削除（日）は CommandLine|contains に
--     'vssadmin delete shadows' のような **空白を含む句** を置いている。実際の
--     コマンドラインは
--         "C:\Windows\system32\vssadmin.exe" delete shadows /all /quiet
--     で、vssadmin と delete の間に .exe" が入るため、この句は原理的に一致しない。
--     'wmic shadowcopy delete' も同じ（実際は wmic.exe shadowcopy delete）。
--     英語版は Image|endswith と CommandLine|contains|all に分けているので当たる。
--
-- (2) LSASS ダンプ（日）は TargetImage|endswith '\lsass.exe' を要求するが、
--     エージェントの credential_access コレクタは target_image を **basename**
--     ("lsass.exe") で出す（agent/internal/collector/credential_access.go の
--     コメントに明記されている設計）。alert_pipeline.go の basename 正規化は
--     対象が Image と ParentImage だけで TargetImage を含まないため一致しない。
--     GrantedAccess 側（実測 0x1410）は一致している。
--
-- 検知能力は落ちない。(1) の固有語彙とされうる bcdedit ... recoveryenabled no は
-- 他の8ルールが押さえている（Inhibit System Recovery (DB) sev9 /
-- Shadow Copy Deletion sev10 / Bootloader or Boot Configuration Tampering (DB)
-- sev8 ほか）。(2) は英語版の Procdump ルールと、コード側の資格情報アクセス検知器
-- （[CRED] 系）が担当する。
--
-- ★ auto_isolate を false にするのが本命である。
--
-- (2) は TargetImage の basename 正規化を入れれば到達可能になるが、同じ条件
-- （TargetImage=lsass.exe かつ GrantedAccess=0x1410）のアクセス元には
-- **Windows Defender の MsMpEng.exe が含まれる**（実測 40 日で 2 件）。この
-- ルールは発信元を絞っておらず auto_isolate=true・severity 9・しきい値 9 なので、
-- 正規化を入れた瞬間に Defender の通常動作でホストが自動隔離される。
-- 「死蔵ルールを到達可能にする前に、なぜ無害だったのかを確認する」の最も危険な形で、
-- 正規化の追加より先にここを外しておく必要がある。
--
-- DELETE ではなく無効化にしている理由: 行が残っていれば、再有効化しようとした者が
-- git blame でこの migration に辿り着き、下記の欠陥に気づける。DELETE すると
-- 「そもそも無かった」のか「意図して落とした」のかが区別できなくなる。
--
-- ★文の形は migration_rules_test.go のハーネスに合わせる。
--
-- 初版は `WHERE name IN (...) AND coalesce(description,'') NOT LIKE '%…%'` と書き、
-- description に理由を追記していた。これは TestEveryUpdateRulesStatementIsUnderstood
-- で落ちる——ハーネスが持つ8つの UPDATE パターンのどれにも一致せず、
-- 「パーサが認識しない入力を飛ばすのはカバレッジに見えるだけだ」として弾かれる。
-- ハーネスが読めない UPDATE は、抽出器が更新前の状態を報告したまま本番だけが
-- 更新後で動く、という乖離を生む。そのためのゲートである。
--
-- そこで `WHERE name = '…'` を1ルールにつき1文ずつ書く（updateFieldsRe が読める形）。
-- description への追記もやめた。`||` による連結はハーネスの SET 解析を無用に
-- 複雑にするうえ、追記をやめれば冪等性のための NOT LIKE も要らなくなる
-- （enabled=false を二度書いても結果は同じ）。無効化の理由はこのコメントと
-- docs/results/live-20260818-jp-duplicate-rules-inert.md に残す。migration の
-- 理由はそこに書くのが本来で、DB の列に埋める必要は無い。

UPDATE rules
SET enabled      = false,
    auto_isolate = false,
    updated_at   = now()
WHERE name = 'シャドウコピー削除コマンド（ランサムウェア）';

UPDATE rules
SET enabled      = false,
    auto_isolate = false,
    updated_at   = now()
WHERE name = 'LSASSメモリダンプ（資格情報窃取）';
