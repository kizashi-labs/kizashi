-- 288: 認証ブルートフォース検知(T1110)の壊れたフィールド参照を修正 + パスワードスプレー追加。
--
-- ★サイレント故障: 既存の auth ブルートフォースルールは `field: eventName` /
-- `value: 4625`(Windows) / `value: ssh_auth_fail`(SSH) を参照していたが、
-- ingestion が正規化する auth イベントのフィールドは
-- {username, action, success, source_ip, auth_method, failure_reason} で、
-- eventName 列も 4625/ssh_auth_fail という値も存在しない(action="failed")。
-- → SequenceEngine が該当フィールドを見つけられず、両ルールは永久に inert
--   = Windows/SSH ブルートフォース検知が黙って一度も発火していなかった。
-- 正しい field:action / value:failed に修正し、group_by を用途別に分けて
-- 「アカウント標的型(username)」と「送信元IP集中型(source_ip)」を相補的にする。

-- (1) Windows 失敗ログオン → アカウント標的型ブルートフォース(T1110.001)
UPDATE rules SET content = $$
# 同一ユーザー名に対する認証失敗が短時間に集中(標的型ブルートフォース)。
# auth イベントの正規化フィールド action=="failed" を数える。
window: 120s
threshold: 8
event_type: auth
field: action
value: failed
group_by: username
$$, mitre_tags = ARRAY['T1110', 'T1110.001'], updated_at = NOW()
WHERE name = 'Windows ログイン失敗の繰り返し';

-- (2) SSH/ネットワーク 失敗ログオン → 送信元IP集中型ブルートフォース(T1110)
UPDATE rules SET content = $$
# 同一送信元IPからの認証失敗が短時間に集中(送信元集中型ブルートフォース)。
# RDP/SMB/SSH 等ネットワークログオンの失敗(source_ip 付き)を相関。
window: 60s
threshold: 5
event_type: auth
field: action
value: failed
group_by: source_ip
$$, mitre_tags = ARRAY['T1110'], updated_at = NOW()
WHERE name = 'SSH ブルートフォース検知';

-- (3) パスワードスプレー(T1110.003): 1送信元から多数の異なるユーザー名へ認証失敗。
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags,
                   auto_isolate, auto_kill, description, enabled)
SELECT 'パスワードスプレー攻撃（多数アカウントへの認証失敗）', 'behavioral', ARRAY['windows', 'linux'], 7,
$$
# 5分以内に同一送信元IPから 5 種類以上の異なるユーザー名に対して認証失敗が
# 発生した場合に検知。少数試行を多数アカウントへ横に広げる=スプレーの典型。
# distinct で「異なるユーザー名の数」を数える。
window: 300s
threshold: 5
event_type: auth
field: action
value: failed
group_by: source_ip
distinct: true
distinct_field: username
$$,
'community', ARRAY['T1110', 'T1110.003'], false, false,
'単一送信元から多数アカウントへの認証失敗（パスワードスプレー）を相関検知。', true
WHERE NOT EXISTS (
    SELECT 1 FROM rules WHERE name = 'パスワードスプレー攻撃（多数アカウントへの認証失敗）'
);
