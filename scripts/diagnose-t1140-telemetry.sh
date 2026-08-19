#!/usr/bin/env bash
# T1140 (Deobfuscate/Decode) が実機測定で MISS になる原因を切り分ける読み取り専用スクリプト。
#
# 背景: 検知率測定で T1140 が繰り返し MISS になったため、当初は「デコード単体を見る
# ルールが無い」と評価した。しかしこれは誤診で、DB には該当コマンドを完全一致で捕捉する
# ルールが2本ある (240 / 342 マイグレーション)。しかも同じ `base64 -d` を含む T1027
# (`echo … | base64 -d | bash`) は同一ランで検知されている。
# つまり差はルールではなく「どのプロセスイベントが実際にサーバへ届いたか」にある。
# 本スクリプトはその一点を DB から確定させる。
# 詳細 = docs/results/live-20260726-detection-rate-scorecard.md §2e
#
#   使い方 (サーバ側リポジトリルートで実行):
#     bash scripts/diagnose-t1140-telemetry.sh              # 直近24時間
#     SINCE='3 days' bash scripts/diagnose-t1140-telemetry.sh
#
# 何も変更しない (SELECT のみ)。出力をそのまま貼れば、
# 「ルール側」「エージェント側の取りこぼし」のどちらかまで切り分けられる。
set -uo pipefail

PG_CONTAINER="${PG_CONTAINER:-kizashi-postgres}"
PG_USER="${PG_USER:-edr}"
PG_DB="${PG_DB:-edrplatform}"
SINCE="${SINCE:-24 hours}"

psql_q() { docker exec -i "$PG_CONTAINER" psql -U "$PG_USER" -d "$PG_DB" -X -q "$@"; }
section() { printf '\n═══ %s ═══\n' "$1"; }

echo "対象期間: 直近 $SINCE / DB: $PG_DB@$PG_CONTAINER"

section "1. T1140 ルールが DB に存在し有効か"
# ここが 0 行なら話は簡単 (ルール未投入 = マイグレーション未適用)。
# 2行出るのが期待値: 240 と 342 の両マイグレーション由来。
psql_q -c "SELECT name, enabled, platform, mitre_tags
           FROM rules
           WHERE 'T1140' = ANY(mitre_tags)
           ORDER BY name;"

section "2. base64 を含むプロセスイベントが届いているか (核心)"
# 測定スクリプトは各テクニックを bash -c \"<cmd>\" で実行するため、届いていれば
# 親 bash の command_line に丸ごと 'base64 -d' が含まれる。
# ここに T1027 の行だけがあり T1140 の行が無ければ、原因はルールではなく
# 「短命プロセスのイベントが届いていない」ことで確定する。
psql_q -c "SELECT time, raw_data->>'process_name' AS proc,
                  left(raw_data->>'command_line', 100) AS cmd
           FROM events
           WHERE event_type = 'process'
             AND raw_data->>'command_line' ILIKE '%base64%'
             AND time > now() - interval '$SINCE'
           ORDER BY time DESC
           LIMIT 30;"

section "3. T1140 / T1027 のアラート発生状況"
psql_q -c "SELECT created_at, mitre_technique, left(title, 70) AS title
           FROM alerts
           WHERE (mitre_technique IN ('T1140','T1027')
                  OR 'T1140' = ANY(ai_mitre_tags)
                  OR 'T1027' = ANY(ai_mitre_tags))
             AND created_at > now() - interval '$SINCE'
           ORDER BY created_at DESC
           LIMIT 20;"

section "4. 短命プロセスがそもそも捕捉できているか (分母の確認)"
# 測定で使う他の短命コマンドが届いているかを見る。ここも空なら T1140 固有の
# 問題ではなく、短命プロセス全般の取りこぼし = プロセスコレクタ側の課題。
psql_q -c "SELECT raw_data->>'process_name' AS proc, count(*) AS n,
                  max(time) AS latest
           FROM events
           WHERE event_type = 'process'
             AND time > now() - interval '$SINCE'
             AND raw_data->>'process_name' IN
                 ('base64','whoami','uname','id','groups','getent','ps','ip','ss','dpkg','rpm')
           GROUP BY 1 ORDER BY n DESC;"

section "5. プロセスイベント全体の到達量 (比較用)"
psql_q -c "SELECT date_trunc('hour', time) AS hour, count(*) AS process_events
           FROM events
           WHERE event_type = 'process' AND time > now() - interval '$SINCE'
           GROUP BY 1 ORDER BY 1 DESC LIMIT 12;"

cat <<'GUIDE'

─── 判定ガイド ───────────────────────────────────────────────
[2] に T1140 の行 (`base64 -d` を含み `| bash` を含まない) がある
    → テレメトリは届いている。原因は RuleEngine 側 (プラットフォーム
       ゲート / フィールド解決 / ルール無効化)。[1] の enabled と platform を確認。

[2] に T1027 の行だけがある
    → 原因はエージェント側の取りこぼしで確定。ルールは無罪。
       同じ秒に複数イベントが出た場合の JetStream 重複排除
       (eventMsgID がイベントID空でタイムスタンプ秒に退化する経路) が
       第一容疑。NetworkEvent で実証済みの既知パターン。

[2] が完全に空 かつ [4] も空
    → 短命プロセス全般が届いていない。T1140 固有ではなくプロセス
       コレクタのカバレッジ問題。[5] が 0 に近ければ収集自体が停止。

いずれの場合も「同じ文字列を狙う3本目のルールを追加する」ことは解決に
ならない ([1] が示すとおりルールは既にある)。
─────────────────────────────────────────────────────────────
GUIDE
