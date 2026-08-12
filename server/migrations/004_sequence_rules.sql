-- 振る舞いシーケンスルール（時間軸相関）の追加
-- window/threshold ディレクティブを持つ behavioral ルールは
-- SequenceEngine によって評価される。

INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags,
                   auto_isolate, auto_kill, description, enabled) VALUES

-- ─── ブルートフォース ──────────────────────────────────────────

('SSH ブルートフォース検知', 'behavioral', ARRAY['linux'], 7,
$$
# 60秒以内に同一エージェントから 5 件以上のSSH認証失敗
window: 60s
threshold: 5
event_type: auth
field: eventName
value: ssh_auth_fail
group_by: agent_id
$$,
'community', ARRAY['T1110.001'], false, false,
'短時間の繰り返しSSH認証失敗からブルートフォース攻撃を検知。', true),

('Windows ログイン失敗の繰り返し', 'behavioral', ARRAY['windows'], 7,
$$
# 120秒以内に同一エージェントから 10 件以上のログオン失敗 (EventID 4625)
window: 120s
threshold: 10
event_type: auth
field: eventName
value: 4625
group_by: agent_id
$$,
'community', ARRAY['T1110.001'], false, false,
'Windows認証失敗の繰り返しを検知 (EventID 4625)。', true),

('RDPブルートフォース検知', 'behavioral', ARRAY['windows'], 8,
$$
# 30秒以内に 8 件以上のRDP失敗
window: 30s
threshold: 8
event_type: network
field: dstPort
value: 3389
group_by: srcIp
$$,
'community', ARRAY['T1110.001'], false, false,
'RDP(3389番ポート)への集中的な接続試行を検知。', true),

-- ─── ネットワーク偵察 ─────────────────────────────────────────

('ポートスキャン検知', 'behavioral', ARRAY['windows', 'linux', 'macos'], 6,
$$
# 10秒以内に同一送信元IPから 15 個以上の異なる宛先ポートへの接続
window: 10s
threshold: 15
event_type: network
distinct: true
distinct_field: dstPort
group_by: srcIp
$$,
'community', ARRAY['T1046'], false, false,
'短時間に多数の異なるポートへ接続する偵察活動を検知。', true),

('内部ネットワーク偵察（横展開）', 'behavioral', ARRAY['windows', 'linux'], 7,
$$
# 30秒以内に同一エージェントから 20 個以上の異なる宛先IPへの接続
window: 30s
threshold: 20
event_type: network
distinct: true
distinct_field: dstIp
group_by: agent_id
$$,
'community', ARRAY['T1018', 'T1135'], false, false,
'短時間に多数の内部ホストへ接続する横展開（ラテラルムーブメント）の偵察を検知。', true),

-- ─── プロセス異常 ─────────────────────────────────────────────

('短時間の大量プロセス生成（コードインジェクション疑い）', 'behavioral', ARRAY['windows', 'linux'], 8,
$$
# 5秒以内に同一エージェントから 30 件以上のプロセス生成
window: 5s
threshold: 30
event_type: process
group_by: agent_id
$$,
'community', ARRAY['T1055', 'T1569'], false, false,
'異常に短時間で大量のプロセスを生成する挙動（ワーム・インジェクション疑い）を検知。', true),

-- ─── DNS ─────────────────────────────────────────────────────

('DNS クエリ急増（DNSトンネリング疑い）', 'behavioral', ARRAY['windows', 'linux', 'macos'], 6,
$$
# 60秒以内に同一エージェントから 100 件以上のDNSクエリ
window: 60s
threshold: 100
event_type: dns
group_by: agent_id
$$,
'community', ARRAY['T1071.004'], false, false,
'短時間の異常に多いDNSクエリからDNSトンネリングやビーコニングを検知。', true),

('多数の異なるドメインへのDNSクエリ（C2探索疑い）', 'behavioral', ARRAY['windows', 'linux', 'macos'], 7,
$$
# 60秒以内に同一エージェントから 50 個以上の異なるドメインへのDNSクエリ
window: 60s
threshold: 50
event_type: dns
distinct: true
distinct_field: query
group_by: agent_id
$$,
'community', ARRAY['T1568', 'T1071.004'], false, false,
'DGAマルウェアやC2通信で見られる多数の異なるドメインへのDNSクエリを検知。', true),

-- ─── 探索・偵察コマンドのバースト ─────────────────────────────

('探索コマンドの短時間バースト（ディスカバリ）', 'behavioral', ARRAY['windows', 'linux'], 6,
$$
# 60秒以内に同一エージェントから 4 種類以上の異なる探索系コマンドが実行された場合に検知。
# 単発の whoami / tasklist 等はノイズだが、短時間に多種が連続するのは
# 侵入直後の状況把握（ディスカバリ）に典型的なシグナル。
# value_any: 列挙したコマンドのいずれかを processName が含めばマッチ（OR）。
# distinct で「異なる種類のコマンド数」を数え、閾値判定する。
window: 60s
threshold: 4
event_type: process
field: processName
value_any: whoami, tasklist, systeminfo, ipconfig, ifconfig, hostname, net.exe, net1.exe, nltest, quser, qwinsta, arp, route, netstat, wmic, nbtstat, dsquery, sc.exe, reg.exe, findstr, wevtutil
distinct: true
distinct_field: processName
group_by: agent_id
$$,
'community', ARRAY['T1033', 'T1057', 'T1082', 'T1016', 'T1018', 'T1087.002', 'T1518.001'], false, false,
'侵入直後に多用される探索系コマンドが短時間に多種実行される挙動（ディスカバリ・バースト）を相関検知。', true),

-- ─── ランサムウェアの一括暗号化 ───────────────────────────────

('ランサムウェアによる一括ファイル暗号化', 'behavioral', ARRAY['windows', 'linux'], 9,
$$
# 60秒以内に同一エージェントで 20 個以上の異なるファイルが
# ランサムウェア拡張子に変化した場合に検知。
# 単一ファイルの改名はノイズだが、短時間の大量改変はランサムウェアの
# 暗号化進行に典型的なシグナル。
# value_any: パスが列挙した拡張子のいずれかを含めばマッチ（OR）。
# distinct_field=path で「異なる暗号化ファイル数」を数え、閾値判定する。
window: 60s
threshold: 20
event_type: file
field: path
value_any: .locked, .encrypted, .crypt, .crypto, .enc, .crypted, .cry, .cerber, .locky, .zepto, .wncry, .wcry, .ryuk, .conti, .lockbit, .makop, .phobos, .djvu, .stop, .sage, .globe, .vault, .xtbl, .nemesis, .aes256, .rsa
distinct: true
distinct_field: path
group_by: agent_id
$$,
'community', ARRAY['T1486'], false, false,
'短時間に多数のファイルがランサムウェア拡張子へ変化する挙動（一括暗号化）を相関検知。', true);
