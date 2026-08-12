-- 359: ネットワークポートスキャン→PsExec/Impacket系横展開の複合キルチェーン。
--
-- 単発のスキャンツール実行(nmap/masscan等)は中程度のシグナルだが、その後短時間で
-- 同一ホストから横展開ツールが実行された場合、偵察→展開という一連の攻撃行動と
-- みなせる強い相関になる。
--
--   ①ネットワークスキャンツール(nmap/masscan/Advanced Port Scanner/portqry)の実行
--   ②PsExec/Impacket系(psexec/wmic node/winrs/Invoke-Command)による横展開
--
-- が30分以内にこの順序で連鎖するのは、内部ネットワークを走査した後に到達可能な
-- ホストへ展開する、侵入テストツールキットにも実際の攻撃者にも共通する典型パターン。
-- ordered:true — スキャンが先、横展開が後。
--
-- rules.name に一意制約が無いので WHERE NOT EXISTS で二重登録を防ぐ（冪等）。

INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags,
                   auto_isolate, auto_kill, description, enabled)
SELECT 'ネットワークスキャン＋横展開キルチェーン（偵察から展開への移行）', 'behavioral', ARRAY['windows'], 8,
$$
# 30分以内に同一エージェントで「ポートスキャンツール実行」→「PsExec/Impacket系
# 横展開」がこの順序で連鎖した場合に検知する、偵察から展開への移行を捉える
# キルチェーン。
window: 30m
stages: 2
ordered: true
event_type: process
field: commandline
stage_1: nmap.exe, masscan.exe, advanced_port_scanner, portqry.exe
stage_2: psexec, psexesvc, wmic /node:, winrs -r:, invoke-command -computername
group_by: agent_id
$$,
'community', ARRAY['T1046', 'T1021.002'], false, false,
'ネットワークポートスキャンツールの実行後、同一ホストからPsExec/Impacket系の横展開が短時間に連鎖する、偵察から展開への移行行動を複合相関で検知。', true
WHERE NOT EXISTS (
    SELECT 1 FROM rules WHERE name = 'ネットワークスキャン＋横展開キルチェーン（偵察から展開への移行）'
);
