-- 273: 探索コマンドのバースト検知 — mitre_tags を value_any のコマンドが対応する
-- ATT&CK 技で網羅し、Linux のサービス探索コマンドを value_any に追加。
--
-- 背景(2026-06-22): バーストは1アラートで複数の Discovery 技を検知するが(相関アラートが
-- 全 mitre_tags に加点する仕組み = engine.go / attack-scorer)、mitre_tags に技が無い
-- コマンドは検知(発火)しても per-technique で加点されない。実測で net localgroup
-- (T1069.001) が Windows/Linux 双方で唯一の MISS だった(タグ漏れ)。
--
-- value_any の各コマンドが対応する技を mitre_tags に補完する(過剰加点はしない —
-- scorer は「実行された run ∧ アラートのタグ一致 ∧ 検知窓内」のみ加点):
--   net localgroup / getent group        → T1069.001 (Permission Groups Discovery)
--   sc.exe / systemctl / service          → T1007     (System Service Discovery)
--   net view / net share                  → T1135     (Network Share Discovery)
--   reg.exe query                         → T1012     (Query Registry)
-- あわせて Linux のサービス探索コマンド(systemctl, service)を value_any に追加。
-- rule は 266/272 で投入済みなので UPDATE で前進(冪等)。

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
value_any: whoami, tasklist, systeminfo, ipconfig, ifconfig, hostname, net.exe, net1.exe, nltest, quser, qwinsta, arp, route, netstat, wmic, nbtstat, dsquery, sc.exe, reg.exe, findstr, wevtutil, ps, id, ss, ip, uname, w, who, last, lastlog, lsof, getent, lscpu, lsblk, lspci, lsmod, dmidecode, hostnamectl, crontab, nmcli, dmesg, systemctl, service
distinct: true
distinct_field: processName
group_by: agent_id
$$,
  mitre_tags = ARRAY['T1033','T1057','T1082','T1016','T1018','T1049','T1083','T1087.001','T1087.002','T1518.001','T1069.001','T1007','T1135','T1012']
WHERE name = '探索コマンドの短時間バースト（ディスカバリ）';
