-- 349: 新規キルチェーン2種。既存(334/339/290等)が未カバーの
--   (1) コンテナ→ホスト脱出 → ホスト永続化/持ち出し (T1611 → 永続化/exfil)
--   (2) クラウドIMDS資格情報窃取 → クラウド列挙/横展開 (T1552.005 → T1580/T1078.004)
-- いずれも commandLine を field に、ordered:true・group_by:agent_id で同一ホスト内の
-- 時間順連鎖に限定。単発ルール(346 のエスケープ検知等)を「その後の行動」と相関して
-- 侵害の進行を高信頼に捉える。冪等: WHERE NOT EXISTS。

-- ── T1611 → 永続化/持ち出し : コンテナ脱出後にホストで居座る/抜く ──────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags,
                   auto_isolate, auto_kill, description, enabled)
SELECT 'コンテナ脱出→ホスト永続化/持ち出しキルチェーン', 'behavioral', ARRAY['linux'], 9,
$$
# コンテナからホストへ脱出(nsenter -t 1 / cgroup release_agent / /proc/1/root)した
# 直後に、ホスト側で永続化(cron/systemd/ld.so.preload)またはツール取得/持ち出し
# (curl/wget/nc)を行う時間順連鎖 = 特権コンテナ侵害の進行(T1611 → 永続化/exfil)。
window: 600s
stages: 2
ordered: true
event_type: process
field: commandLine
stage_1: nsenter --target 1, nsenter -t 1, release_agent, notify_on_release, /proc/1/root
stage_2: crontab, systemctl enable, /etc/ld.so.preload, /etc/cron, curl http, wget http, nc -e, chattr +i
group_by: agent_id
$$,
'community', ARRAY['T1611', 'T1053.003', 'T1574.006', 'T1105'], false, false,
'コンテナ→ホスト脱出の直後にホスト永続化/ツール取得/持ち出しが続く侵害進行を相関検知。', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'コンテナ脱出→ホスト永続化/持ち出しキルチェーン');

-- ── T1552.005 → T1580/T1078.004 : IMDS資格情報窃取 → クラウド列挙 ──────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags,
                   auto_isolate, auto_kill, description, enabled)
SELECT 'クラウドIMDS窃取→クラウド列挙キルチェーン', 'behavioral', ARRAY['linux', 'windows'], 8,
$$
# インスタンスメタデータ(169.254.169.254 / metadata.google.internal / iam/security-
# credentials)へアクセスして一時資格情報を窃取した直後に、盗んだ資格情報でクラウド
# リソースを列挙/操作する時間順連鎖(T1552.005 → T1580/T1078.004)。SSRF やコンテナ
# 侵害からのクラウド侵入で頻出。
window: 900s
stages: 2
ordered: true
event_type: process
field: commandLine
stage_1: 169.254.169.254, metadata.google.internal, latest/meta-data/iam, security-credentials, metadata/identity/oauth2
stage_2: aws sts get-caller-identity, aws s3 ls, aws ec2 describe, aws iam list, gcloud , az account, az vm list, aws configure
group_by: agent_id
$$,
'community', ARRAY['T1552.005', 'T1580', 'T1078.004', 'T1087.004'], false, false,
'インスタンスメタデータからの一時資格情報窃取の直後にクラウド列挙/操作が続くクラウド侵入連鎖を相関検知。', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'クラウドIMDS窃取→クラウド列挙キルチェーン');
