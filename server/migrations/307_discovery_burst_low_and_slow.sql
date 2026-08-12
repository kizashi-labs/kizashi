-- 307: 探索コマンドのバースト検知を「低速・分散偵察」耐性化。
--
-- 背景: Caldera 実走(2026-07-04, 7レポート集計)で、Discovery 系の技術
--   (T1018/T1033/T1057/T1069.001/T1087.001/T1135/T1518.001) が可視性はあるのに
--   Technique まで分類されず Telemetry 止まりだった。単発スコアカードでは同一技術が
--   探索バーストで Technique 判定される一方、Caldera では未発火 —— 原因は本ルールの
--   観測窓が 60 秒と狭く、コマンド間にジッター(遅延)を挟む現実的な偵察が
--   「60 秒以内に 4 種」の条件を外していたため。
--
-- 対策: 観測窓を 60s → 10m に拡張し、幅(distinct なコマンド種別数)で検知する。
--   速いバーストも広い窓に収まるため即時検知の性質は失わない(閾値到達と同時に発火)。
--   窓拡張による誤検知(FP)増を相殺するため閾値を 4 → 5 に引き上げる。5 種類以上の
--   異なる探索コマンドが単一エージェントから連続するのは、正規の運用では稀で、
--   侵入直後の状況把握に典型的なシグナル。既定 5 分クールダウンがアラート量を抑制する。
--
-- rule は 266(投入)/272(Linux 追記)で存在するので UPDATE で content を前進(冪等)。
-- value_any / mitre_tags は 272 の内容を保持する。

UPDATE rules SET
  content = $$
# 10分以内に同一エージェントから 5 種類以上の異なる探索系コマンドが実行された場合に検知。
# 単発の whoami / ps 等はノイズだが、多種が(間隔を空けてでも)連続するのは
# 侵入直後の状況把握（ディスカバリ）に典型的なシグナル。低速・分散した偵察も捕捉するため
# 観測窓を広く取り、コマンドの「幅」(distinct な種別数)で判定する。
# value_any: 列挙したコマンドのいずれかと processName（Windows は含有 / Linux はベース名一致）がマッチ。
# distinct で「異なる種類のコマンド数」を数え、閾値判定する。
window: 10m
threshold: 5
event_type: process
field: processName
value_any: whoami, tasklist, systeminfo, ipconfig, ifconfig, hostname, net.exe, net1.exe, nltest, quser, qwinsta, arp, route, netstat, wmic, nbtstat, dsquery, sc.exe, reg.exe, findstr, wevtutil, ps, id, ss, ip, uname, w, who, last, lastlog, lsof, getent, lscpu, lsblk, lspci, lsmod, dmidecode, hostnamectl, crontab, nmcli, dmesg
distinct: true
distinct_field: processName
group_by: agent_id
$$,
  mitre_tags = ARRAY['T1033','T1057','T1082','T1016','T1018','T1049','T1083','T1069.001','T1087.001','T1087.002','T1135','T1518.001']
WHERE name = '探索コマンドの短時間バースト（ディスカバリ）';
