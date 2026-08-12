-- 290: 相関(多段キルチェーン)ルールを追加。既存の「ハンズオン侵入キルチェーン
-- (偵察→認証情報→横展開)」がカバーしない2つの侵入シーケンスを SequenceEngine の
-- staged ルールで検知する。個々の段階は単発では発火閾値以下でも、短時間に順序
-- 連鎖すると hands-on-keyboard 侵入の強いシグナルになる。
--
-- staged ルールは単一 event_type / 単一 field(commandLine)に対する SUBSTRING 一致。
-- 具体トークン("vssadmin delete" 等)を選び FP を抑える。ordered:true で時間順を要求。

-- (1) 防御回避 → ペイロード取得(T1562.001 → T1105)。
--     セキュリティ機能の無効化直後に LOLBin でペイロードをダウンロードする連鎖。
--     Defender/FW 無効化は正規操作では稀で、ダウンロードとの近接連鎖は高シグナル。
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags,
                   auto_isolate, auto_kill, description, enabled)
SELECT '防御回避→ペイロード取得キルチェーン', 'behavioral', ARRAY['windows'], 8,
$$
# 10分以内に「セキュリティ機能の無効化」→「LOLBinによるダウンロード」が
# この順で発生した場合に検知(T1562.001 → T1105)。
window: 10m
stages: 2
ordered: true
event_type: process
field: commandLine
stage_1: set-mppreference -disablerealtimemonitoring, sc stop windefend, sc config windefend, net stop windefend, netsh advfirewall set allprofiles state off, add-mppreference -exclusionpath, disable-windowsoptionalfeature, wevtutil cl, fsutil usn deletejournal
stage_2: certutil -urlcache, certutil.exe -urlcache, bitsadmin /transfer, invoke-webrequest, iwr , (new-object net.webclient).downloadfile, start-bitstransfer, curl http, curl -o, wget http
group_by: agent_id
$$,
'community', ARRAY['T1562.001', 'T1105'], false, false,
'セキュリティ機能の無効化直後に LOLBin でペイロードを取得する多段攻撃を相関検知。', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = '防御回避→ペイロード取得キルチェーン');

-- (2) 収集 → 持ち出し(T1560 → T1041/T1567)。
--     データをアーカイブ圧縮した直後に外部へアップロードする連鎖。
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags,
                   auto_isolate, auto_kill, description, enabled)
SELECT 'データ収集→持ち出しキルチェーン', 'behavioral', ARRAY['windows', 'linux'], 7,
$$
# 15分以内に「アーカイブ圧縮」→「外部アップロード」がこの順で発生した場合に
# 検知(T1560 収集 → T1041/T1567 持ち出し)。圧縮とアップロードの近接連鎖は
# データ持ち出しの典型シーケンス。
window: 15m
stages: 2
ordered: true
event_type: process
field: commandLine
stage_1: compress-archive, 7z a, 7za a, rar a, winrar, tar czf, tar -czf, tar cjf, zip -r, makecab
stage_2: curl -t, curl --upload-file, invoke-restmethod -method put, invoke-webrequest -method put, bitsadmin /upload, scp , sftp , ftp -s, (new-object net.webclient).uploadfile, start-bitstransfer -transfertype upload
group_by: agent_id
$$,
'community', ARRAY['T1560', 'T1041', 'T1567'], false, false,
'データのアーカイブ圧縮直後に外部へアップロードする収集→持ち出しの多段攻撃を相関検知。', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'データ収集→持ち出しキルチェーン');
