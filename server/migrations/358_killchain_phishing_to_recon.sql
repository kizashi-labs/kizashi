-- 358: フィッシング実行(Officeからのスクリプト起動)→初動偵察コマンドの複合キルチェーン。
--
-- 既存のキルチェーン(274/290/304/306/318/319)は侵害の中盤〜終盤（資格情報ダンプ、
-- 横展開、ランサムウェア、永続化確立）に偏っており、初動アクセス直後の段階を
-- 捉えるものが無かった。本ルールは「Officeアプリがスクリプトインタプリタ/LOLBinを
-- 起動した」（単発Sigmaルール「Office Application Spawning Script Interpreter」と
-- 同じ兆候）の直後に、同一エージェントで偵察コマンドが実行された場合に発火する。
--
--   ①Officeアプリ(winword/excel/powerpnt/outlook/mspub)が子プロセスを起動
--   ②その後、状況把握コマンド(whoami/systeminfo/net view/nltest/wmic os get/
--     ipconfig /all)が実行される
--
-- が10分以内にこの順序で連鎖するのは、マクロ経由の初期侵害の直後に攻撃者(または
-- 自動化されたステージャ)が状況把握を行う典型パターン。ordered:true — フィッシング
-- 実行が先、偵察が後（逆順は無関係な事象の可能性が高いため連鎖とみなさない）。
-- stage_1_field は子プロセスイベントの parent_image_path を見るため、単発では
-- 見えない「フィッシング文書からの実行」を捉える。
--
-- rules.name に一意制約が無いので WHERE NOT EXISTS で二重登録を防ぐ（冪等）。

INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags,
                   auto_isolate, auto_kill, description, enabled)
SELECT 'フィッシング実行＋初動偵察キルチェーン（マクロ経由侵害の直後行動）', 'behavioral', ARRAY['windows'], 8,
$$
# 10分以内に同一エージェントで「Officeアプリからのスクリプト起動」→「偵察コマンド
# 実行」がこの順序で連鎖した場合に検知する、初動アクセス直後を捉えるキルチェーン。
window: 10m
stages: 2
ordered: true
stage_1_event_type: process
stage_1_field: parent_image_path
stage_1: winword.exe, excel.exe, powerpnt.exe, outlook.exe, mspub.exe
stage_2_event_type: process
stage_2_field: commandline
stage_2: whoami, systeminfo, net view, nltest, wmic os get, ipconfig /all
group_by: agent_id
$$,
'community', ARRAY['T1566.001', 'T1082', 'T1018'], false, false,
'Officeアプリがスクリプトインタプリタ/LOLBinを起動した直後、同一ホストで状況把握コマンドが実行される、マクロ経由の初動侵害に典型的な行動を複合相関で検知。', true
WHERE NOT EXISTS (
    SELECT 1 FROM rules WHERE name = 'フィッシング実行＋初動偵察キルチェーン（マクロ経由侵害の直後行動）'
);
