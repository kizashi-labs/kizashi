-- 304: 相関(多段キルチェーン)ルールを拡充。既存(274 ハンズオン侵入 / 290 防御回避
-- →DL・収集→持出)がカバーしない3つの高シグナル侵入シーケンスを SequenceEngine の
-- staged ルールで追加検知する。個々の段階は単発では発火閾値以下でも、短時間に順序
-- 連鎖すると強い侵入シグナルになる。
--
-- staged ルールは単一 event_type / 単一 field(commandLine)への SUBSTRING 一致。
-- 具体トークンを選び FP を抑える。ordered:true で時間順を要求、group_by:agent_id で
-- 同一ホスト内の連鎖に限定。

-- (1) 認証情報奪取 → 横展開(T1003 → T1021)。
--     LSASS/SAM ダンプ直後にリモート実行で他ホストへ展開する hands-on 侵入の中核連鎖。
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags,
                   auto_isolate, auto_kill, description, enabled)
SELECT '認証情報奪取→横展開キルチェーン', 'behavioral', ARRAY['windows'], 9,
$$
# 15分以内に「認証情報ダンプ」→「リモート実行」がこの順で発生した場合に検知
# (T1003 → T1021)。LSASS/SAM 奪取と横展開の近接連鎖は侵入進行の強シグナル。
window: 15m
stages: 2
ordered: true
event_type: process
field: commandLine
stage_1: comsvcs.dll, minidump, procdump, sekurlsa::, lsass.dmp, reg save hklm\sam, reg save hklm\system, reg.exe save hklm\sam, ntdsutil, mimikatz
stage_2: psexec, wmic /node:, winrs -r:, invoke-command -computername, sc \\, schtasks /s , /node: process call create, enter-pssession -computername, wmiexec
group_by: agent_id
$$,
'community', ARRAY['T1003', 'T1003.001', 'T1021'], false, false,
'認証情報ダンプ直後にリモート実行で横展開する多段攻撃を相関検知。', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = '認証情報奪取→横展開キルチェーン');

-- (2) 復旧阻害キルチェーン(T1490)。ランサムウェアが暗号化前にシャドウコピーを削除し
--     起動時復旧を無効化する典型連鎖。いずれも正規操作では極めて稀。
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags,
                   auto_isolate, auto_kill, description, enabled)
SELECT 'ランサムウェア復旧阻害キルチェーン', 'behavioral', ARRAY['windows'], 9,
$$
# 10分以内に「シャドウコピー/バックアップ削除」→「起動時復旧の無効化」がこの順で
# 発生した場合に検知(T1490)。ランサムウェア暗号化前の準備シーケンス。
window: 10m
stages: 2
ordered: true
event_type: process
field: commandLine
stage_1: vssadmin delete shadows, vssadmin.exe delete, wmic shadowcopy delete, win32_shadowcopy, wbadmin delete backup, wbadmin delete catalog, delete systemstatebackup
stage_2: bcdedit /set, recoveryenabled no, bootstatuspolicy ignoreallfailures, cipher /w, fsutil usn deletejournal
group_by: agent_id
$$,
'community', ARRAY['T1490'], false, false,
'シャドウコピー削除直後に起動時復旧を無効化するランサムウェア準備連鎖を相関検知。', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'ランサムウェア復旧阻害キルチェーン');

-- (3) 実行 → 永続化(T1059 → T1547/T1053)。難読化実行やLOLBin実行の直後に自動起動を
--     仕込む連鎖。単発の永続化操作より、実行との近接連鎖の方が悪性度が高い。
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags,
                   auto_isolate, auto_kill, description, enabled)
SELECT '実行→永続化キルチェーン', 'behavioral', ARRAY['windows'], 8,
$$
# 15分以内に「難読化/LOLBin実行」→「自動起動の登録」がこの順で発生した場合に検知
# (T1059 → T1547 Run キー / T1053 スケジュールタスク / サービス作成)。
window: 15m
stages: 2
ordered: true
event_type: process
field: commandLine
stage_1: powershell -enc, powershell.exe -enc, -encodedcommand, frombase64string, mshta http, mshta vbscript, regsvr32 /i:http, regsvr32 /s /u /i:, rundll32 javascript:, iex(, invoke-expression
stage_2: schtasks /create, reg add hkcu\software\microsoft\windows\currentversion\run, reg add hklm\software\microsoft\windows\currentversion\run, currentversion\runonce, new-service, sc create, new-scheduledtask, currentversion\policies\explorer\run
group_by: agent_id
$$,
'community', ARRAY['T1059', 'T1547.001', 'T1053.005'], false, false,
'難読化/LOLBin 実行直後に自動起動を登録する実行→永続化の多段攻撃を相関検知。', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = '実行→永続化キルチェーン');
