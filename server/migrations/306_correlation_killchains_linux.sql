-- 306: Linux 向けの相関(多段キルチェーン)ルールを追加。既存の staged ルール
-- (274/290/304)は主に Windows commandLine を対象にしていたため、Linux 側の
-- 多段侵入シーケンスを SequenceEngine で補う。単発では閾値以下でも短時間に順序
-- 連鎖すると強い侵入シグナルになる。
--
-- staged ルールは単一 event_type / 単一 field(commandLine)への SUBSTRING 一致
-- (小文字化・OR)。具体トークンを選び FP を抑える。ordered:true・group_by:agent_id。

-- (1) マルウェア投下連鎖(T1105 → T1222)。/tmp・/dev/shm への取得直後に実行権を
--     付与する fileless マルウェアの典型的な投下シーケンス。
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags,
                   auto_isolate, auto_kill, description, enabled)
SELECT 'Linux マルウェア投下キルチェーン', 'behavioral', ARRAY['linux'], 8,
$$
# 10分以内に「一時領域へのダウンロード」→「実行権付与」がこの順で発生した場合に
# 検知(T1105 → T1222)。/tmp・/dev/shm への drop と chmod +x の近接連鎖。
window: 10m
stages: 2
ordered: true
event_type: process
field: commandLine
stage_1: wget http, curl http, curl -s http, curl -o /tmp, curl -o /dev/shm, wget -o /tmp, wget -q http, curl -fssl
stage_2: chmod +x /tmp, chmod 777 /tmp, chmod 755 /tmp, chmod u+x /tmp, chmod +x /dev/shm, chmod 777 /dev/shm
group_by: agent_id
$$,
'community', ARRAY['T1105', 'T1222.002'], false, false,
'一時領域へのダウンロード直後に実行権を付与する Linux マルウェア投下連鎖を相関検知。', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Linux マルウェア投下キルチェーン');

-- (2) 防御回避 → 永続化(T1562/T1070 → T1053/T1543)。監査/ログの無効化・消去
--     直後に自動起動を仕込む連鎖。セキュリティ無効化と永続化の近接は高シグナル。
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags,
                   auto_isolate, auto_kill, description, enabled)
SELECT 'Linux 防御回避→永続化キルチェーン', 'behavioral', ARRAY['linux'], 8,
$$
# 15分以内に「監査/ログ無効化・履歴消去」→「永続化登録」がこの順で発生した場合に
# 検知(T1562/T1070 → T1053 cron / T1543 systemd)。
window: 15m
stages: 2
ordered: true
event_type: process
field: commandLine
stage_1: setenforce 0, systemctl stop auditd, service auditd stop, auditctl -e 0, history -c, unset histfile, rm -f ~/.bash_history, truncate -s 0 /var/log, iptables -f
stage_2: crontab -, /etc/cron.d/, /etc/cron.hourly, systemctl enable, /etc/rc.local, /etc/systemd/system, chattr +i, echo * * * *, /etc/init.d/
group_by: agent_id
$$,
'community', ARRAY['T1562.001', 'T1070.003', 'T1053.003', 'T1543.002'], false, false,
'監査/ログの無効化直後に自動起動を仕込む Linux 防御回避→永続化の連鎖を相関検知。', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Linux 防御回避→永続化キルチェーン');

-- (3) 認証情報アクセス → 持ち出し(T1003/T1552 → T1041/T1048)。機密ファイルの
--     読み取り直後に外部へ送出する連鎖。読み取り+送出の近接は窃取の典型。
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags,
                   auto_isolate, auto_kill, description, enabled)
SELECT 'Linux 認証情報窃取→持ち出しキルチェーン', 'behavioral', ARRAY['linux'], 9,
$$
# 15分以内に「機密ファイルの読み取り」→「外部送出」がこの順で発生した場合に検知
# (T1003/T1552 → T1041/T1048)。/etc/shadow・SSH/クラウド鍵の読取と送出の近接連鎖。
window: 15m
stages: 2
ordered: true
event_type: process
field: commandLine
stage_1: cat /etc/shadow, /etc/shadow, .ssh/id_rsa, cat ~/.aws/credentials, .aws/credentials, unshadow, gcore , cat /proc/, cp /etc/shadow
stage_2: curl --upload-file, curl -t , curl -x post, curl -d @, curl --data-binary @, wget --post-file, scp /etc, scp ~/.ssh, nc -w, base64 /etc/shadow
group_by: agent_id
$$,
'community', ARRAY['T1003.008', 'T1552.004', 'T1041', 'T1048'], false, false,
'機密ファイルの読み取り直後に外部送出する Linux 認証情報窃取→持ち出しの連鎖を相関検知。', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Linux 認証情報窃取→持ち出しキルチェーン');
