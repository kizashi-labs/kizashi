-- 274: ハンズオン侵入キルチェーン（偵察→認証情報アクセス→横展開）の多段相関ルール。
--
-- SequenceEngine の新しい「staged（多段）」ルール形式を用いる。単一イベントでは
-- 各ステップが警報閾値未満・あるいは一見正規に見えても、10分以内に
--   ①偵察（whoami/nltest/net group 等）
--   ②認証情報アクセス（reg save/lsadump/ntdsutil/procdump 等）
--   ③横展開（psexec/winrs/wmic /node 等）
-- が「この順序で」連鎖するのは、ハンズオン・キーボード型侵入に極めて典型的な
-- 強いシグナル。ordered:true により管理者の通常作業との誤検知を抑える。
-- field=commandLine の部分一致（特定トークン）で低FPを担保。
--
-- rules.name に一意制約が無いので WHERE NOT EXISTS で二重登録を防ぐ（冪等）。

INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags,
                   auto_isolate, auto_kill, description, enabled)
SELECT 'ハンズオン侵入キルチェーン（偵察→認証情報→横展開）', 'behavioral', ARRAY['windows'], 9,
$$
# 10分以内に同一エージェントで「偵察 → 認証情報アクセス → 横展開」が
# この順序で連鎖した場合に検知する多段（staged）キルチェーンルール。
# 各ステージは commandLine の部分一致トークン（OR）。ordered:true で時系列順を要求。
window: 10m
stages: 3
ordered: true
event_type: process
field: commandLine
stage_1: whoami, nltest, net group, net localgroup, net view, dsquery, quser, klist, net accounts
stage_2: reg save, lsadump, sekurlsa, dcsync, ntdsutil, comsvcs, minidump, procdump, mimikatz, rubeus, vaultcmd
stage_3: psexec, psexesvc, winrs, wmic /node, /node:, invoke-command -computername, enter-pssession, new-pssession -computername, schtasks /s
group_by: agent_id
$$,
'community', ARRAY['T1003', 'T1021.002', 'T1021.006', 'T1033'], false, false,
'偵察→認証情報アクセス→横展開がこの順序で短時間に連鎖するハンズオン侵入を多段相関で検知。', true
WHERE NOT EXISTS (
    SELECT 1 FROM rules WHERE name = 'ハンズオン侵入キルチェーン（偵察→認証情報→横展開）'
);
