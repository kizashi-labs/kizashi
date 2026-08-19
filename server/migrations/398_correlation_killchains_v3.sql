-- 334: 多段キルチェーン相関の拡充 v3。既存(274 偵察→認証情報→横展開 / 290 防御回避
-- →DL・収集→持出 / 304 認証情報→横展開・復旧阻害・実行→永続化 / 306 Linux)が
-- カバーしない2つの高シグナル侵入シーケンスを SequenceEngine の staged ルールで追加。
--
-- staged ルールは単一 event_type / 単一 field(commandLine)への SUBSTRING 一致。
-- ordered:true で時間順、group_by:agent_id で同一ホスト内連鎖に限定。単発では閾値以下
-- でも短時間の順序連鎖は強い侵入シグナル。

-- (1) 権限昇格 → 認証情報アクセス(T1548.002/T1134 → T1003)。
--     UAC バイパス/トークン奪取で昇格した直後に LSASS/SAM をダンプする post-exploitation
--     の中核連鎖。既存の「認証情報→横展開」とは先頭段(昇格)が異なり非重複。
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags,
                   auto_isolate, auto_kill, description, enabled)
SELECT '権限昇格→認証情報アクセスキルチェーン', 'behavioral', ARRAY['windows'], 9,
$$
# 15分以内に「昇格(UACバイパス/トークン奪取)」→「認証情報ダンプ」がこの順で発生
# した場合に検知(T1548.002/T1134 → T1003)。昇格直後の資格情報窃取は侵入進行の強シグナル。
window: 15m
stages: 2
ordered: true
event_type: process
field: commandLine
stage_1: fodhelper, computerdefaults, eventvwr.exe, sdclt.exe, wsreset.exe, slui.exe, token::elevate, getsystem, incognito, bypassuac
stage_2: comsvcs.dll, minidump, procdump, sekurlsa, lsass.dmp, reg save hklm\sam, reg save hklm\system, reg.exe save hklm\sam, ntdsutil, mimikatz
group_by: agent_id
$$,
'community', ARRAY['T1548.002', 'T1134', 'T1003', 'T1003.001'], false, false,
'UACバイパス/トークン奪取で昇格した直後に認証情報をダンプする多段攻撃を相関検知。', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = '権限昇格→認証情報アクセスキルチェーン');

-- (2) スクリプトレット実行 → ペイロード取得(T1218/T1059 → T1105)。
--     HTA/スクリプトレット(mshta/regsvr32 COM scriptlet/rundll32 javascript)で着地
--     した後にダウンロードクレードルで次段を取得する配送連鎖。powershell -enc 等の
--     正規自動化と紛れやすいトークンは先頭段から除外して FP を抑える。
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags,
                   auto_isolate, auto_kill, description, enabled)
SELECT 'スクリプトレット実行→ペイロード取得キルチェーン', 'behavioral', ARRAY['windows'], 8,
$$
# 10分以内に「HTA/スクリプトレット実行」→「ダウンロードクレードル」がこの順で発生
# した場合に検知(T1218.005/T1218.010 → T1105)。着地スクリプトが次段を取得する配送連鎖。
window: 10m
stages: 2
ordered: true
event_type: process
field: commandLine
stage_1: mshta, .hta, regsvr32 /i:, /s /n /u /i:, scrobj.dll, rundll32 javascript:, wscript //e:jscript, cscript //e:jscript
stage_2: certutil -urlcache, certutil.exe -urlcache, downloadstring, downloadfile, invoke-webrequest, iwr http, bitsadmin /transfer, curl -o, wget http
group_by: agent_id
$$,
'community', ARRAY['T1218.005', 'T1218.010', 'T1105'], false, false,
'HTA/スクリプトレットで着地後にダウンロードクレードルで次段を取得する配送連鎖を相関検知。', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'スクリプトレット実行→ペイロード取得キルチェーン');
