-- 360: 資格情報ファイル探索→外部への持ち出しの複合キルチェーン。
--
-- 単発のfindstr/grepによる資格情報探索(T1552.001、既存Sigmaビルトイン
-- 「Credential Harvesting via File Search」と同じ兆候)は中程度のシグナルだが、
-- その直後に外部への転送コマンドが実行された場合、実際にデータが持ち出された
-- 強い証拠に格上げできる。
--
--   ①findstr/grepによるpassword/credentialキーワードのファイル内探索
--   ②git push・curl/scp/ftpによる外部への転送
--
-- が20分以内にこの順序で連鎖するのは、認証情報を発見した直後に外部へ送信する、
-- 資格情報窃取の完了パターン。ordered:true — 探索が先、転送が後。severity 9
-- （既存の資格情報アクセス単体ルールより高い＝実際の持ち出しの証拠のため）。
--
-- rules.name に一意制約が無いので WHERE NOT EXISTS で二重登録を防ぐ（冪等）。

INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags,
                   auto_isolate, auto_kill, description, enabled)
SELECT '資格情報ファイル探索＋外部持ち出しキルチェーン（認証情報窃取の完了）', 'behavioral', ARRAY['windows'], 9,
$$
# 20分以内に同一エージェントで「findstr/grepによる資格情報探索」→「外部への
# ファイル転送」がこの順序で連鎖した場合に検知する、資格情報窃取の完了を捉える
# キルチェーン。
window: 20m
stages: 2
ordered: true
event_type: process
field: commandline
stage_1: findstr /s password, findstr /si password, grep -r password, grep -r credential
stage_2: git push, curl -t , curl --upload-file, ftp -s, scp , (new-object net.webclient).uploadfile
group_by: agent_id
$$,
'community', ARRAY['T1552.001', 'T1567.001'], false, false,
'findstr/grepによる資格情報ファイル探索の直後、同一ホストから外部への転送コマンドが短時間に連鎖する、資格情報窃取が完了し持ち出しに至った強い証拠を複合相関で検知。', true
WHERE NOT EXISTS (
    SELECT 1 FROM rules WHERE name = '資格情報ファイル探索＋外部持ち出しキルチェーン（認証情報窃取の完了）'
);
