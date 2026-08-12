-- 272: 探索コマンドのバースト検知 value_any に Linux ディスカバリコマンドを追加。
--
-- migration 266 の value_any は Windows コマンド中心(whoami/tasklist/ipconfig/...)で、
-- Linux の terse なコマンド(ps/id/ss/ip/uname 等)が未収録だった。実機の広域 ATT&CK
-- 測定(2026-06-22)で、Linux の Discovery が偵察バーストに乗らない(=未検知)ことが判明。
-- value_any のマッチを「ベース名・拡張子除去の完全一致」へ変更(sequence_engine.go)した
-- ことで、短い Linux コマンド名も誤マッチ(ss≒sshd 等)無く列挙できるようになったため追記。
-- rule は 266 で投入済みなので UPDATE で content / mitre_tags を前進させる(冪等)。

UPDATE rules SET
  content = $$
# 60秒以内に同一エージェントから 4 種類以上の異なる探索系コマンドが実行された場合に検知。
# 単発の whoami / ps 等はノイズだが、短時間に多種が連続するのは
# 侵入直後の状況把握（ディスカバリ）に典型的なシグナル。
# value_any: 列挙したコマンドのいずれかと processName のベース名が一致すればマッチ。
# distinct で「異なる種類のコマンド数」を数え、閾値判定する。
window: 60s
threshold: 4
event_type: process
field: processName
value_any: whoami, tasklist, systeminfo, ipconfig, ifconfig, hostname, net.exe, net1.exe, nltest, quser, qwinsta, arp, route, netstat, wmic, nbtstat, dsquery, sc.exe, reg.exe, findstr, wevtutil, ps, id, ss, ip, uname, w, who, last, lastlog, lsof, getent, lscpu, lsblk, lspci, lsmod, dmidecode, hostnamectl, crontab, nmcli, dmesg
distinct: true
distinct_field: processName
group_by: agent_id
$$,
  mitre_tags = ARRAY['T1033','T1057','T1082','T1016','T1018','T1049','T1083','T1087.001','T1087.002','T1518.001']
WHERE name = '探索コマンドの短時間バースト（ディスカバリ）';
