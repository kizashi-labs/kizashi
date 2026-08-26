#!/usr/bin/env bash
# run-atomics.sh — Linux 被験 VM で簡易テクニックを実行し runlog CSV を出力する。
#
# pwsh + Invoke-AtomicRedTeam が使える環境なら run-atomics.ps1 を推奨
# (より網羅的)。本スクリプトは pwsh を入れられない環境向けの最小版で、
# テクニックID と実行コマンドの対応表(下記 TIER*_TECHNIQUES)を直接実行し、
# 開始/終了時刻を RFC3339(UTC) で記録する。
#
#   使い方: ./run-atomics.sh [out.csv] [scenario]
#   採点  : attack-scorer -server <URL> -token <TOKEN> -runlog out.csv
#
# 第2引数 scenario を渡すと全テクニックを1つの多段攻撃チェーンとしてタグ付けし、
# attack-scorer がチェーン採点(段ごと + 連鎖断ち切り率, MITRE Evals 形式)を行う。
#
# ── ティア構成（docs/ATT&CK検知率測定計画.md §4）────────────────────────
# TIER1: 実装済み・Technique 特定が期待できる（必達）
# TIER2: 単一イベントで Telemetry〜General が期待できるディスカバリ群
# TIER3: 未対応見込み。**MISS を正直に記録するために必ず測る**。
#        「測らなかった項目を成功率に含めない」のが他社比較で最も誠実であり、
#        Tier3 を外すと得意領域だけを測った過大な検知率になる。
#
# 実行ティアは環境変数 TIERS で選択できる（既定は全ティア）:
#   TIERS="1,2" ./run-atomics.sh   # Tier3 を除く（非推奨: 数値が甘くなる）
#   TIERS="3"   ./run-atomics.sh   # 弱点だけを再測定
#
# ── 実行ペース ────────────────────────────────────────────────────────
# 単発ルールで検知される技術は SETTLE_SECONDS 間隔（採点窓より長くすること）、
# 探索群(Tier2)は DISCOVERY_PACE 間隔で密に流す。両者を同じ間隔で流すと、疎にすれば
# 相関検知器を過小評価し、密にすれば採点窓が相互汚染する（どちらも数値が実力を表さない）。
#   SETTLE_SECONDS=90 DISCOVERY_PACE=15 ./run-atomics.sh out.csv
#
# ⚠ 隔離された検証用 VM でのみ実行すること。docs/ATT&CK検知率測定計画.md 参照。
# ⚠ 収録テストはすべて「良性・自己完結・後始末込み」。永続化の作成、セキュリティ
#   機能の無効化、ファイアウォール変更など、ホストの状態を壊す操作は入れない。
set -u

OUT="${1:-runlog.csv}"
SCENARIO="${2:-}"
SETTLE="${SETTLE_SECONDS:-8}"
TIERS="${TIERS:-1,2,3}"
# 相関検知器を正当に評価するためのディスカバリ専用ペース。
# 探索テクニックは単発ルールを持たず、バースト相関(窓5分/4種以上)でのみ Technique 判定を
# 得る。ところが採点の相互汚染を避けるため間隔を窓より長くすると、窓に閾値ぶんの技術が
# 揃わなくなり、どれが検知されるかがタイミング次第の非決定になる（実測で同一ビルドが
# 76%〜82% に振れた）。「間隔＞窓」と「相関成立に必要な密度」は同時に満たせない。
# そこで探索群だけは攻撃実態に近い密度で1シナリオとして流し、単発ルールで検知される
# 技術は疎な間隔で個別評価する。詳細＝docs/ATT&CK検知率測定計画.md §9。
DISCOVERY_PACE="${DISCOVERY_PACE:-15}"

# "Txxxx|テスト名|実行コマンド" の行を追加すれば測定対象を拡張できる。

# ── Tier 1: 実行系（Technique 特定が期待できる）──────────────────────
TIER1_TECHNIQUES=(
  "T1059.004|T1 bash one-liner|-|bash -c 'echo benign-test-\$\$ >/dev/null'"
)

# ── Tier 2: ディスカバリ群（Telemetry〜Technique が期待できる）────────
TIER2_TECHNIQUES=(
  "T1033|T2 whoami|burst|whoami"
  "T1057|T2 process discovery|burst|ps aux"
  "T1082|T2 system info|burst|uname -a"
  "T1016|T2 network config|burst|ip addr"
  "T1018|T2 remote discovery|burst|cat /etc/hosts"
  # T1518 is software discovery; `which` was previously used here under the
  # T1518.001 label, which was wrong twice over — `which` is far too generic to
  # classify (every shell script runs it) and .001 is SECURITY software discovery,
  # a different behaviour. Measure each with a command that actually represents it.
  "T1518|T2 software discovery|burst|dpkg -l 2>/dev/null | head -20 || rpm -qa 2>/dev/null | head -20"
  "T1518.001|T2 security software discovery|burst|ps aux | grep -i -E 'falcon|crowdstrike|clamav|sentinelone' | head -5; systemctl status clamav 2>/dev/null | head -3 || true"
  "T1087.001|T2 local account discovery|burst|tail -5 /etc/passwd"
  "T1069.001|T2 local group discovery|burst|groups; getent group sudo"
  "T1049|T2 network connections|burst|ss -tun 2>/dev/null || netstat -tun"
  "T1007|T2 system service discovery|burst|systemctl list-units --type=service --no-pager 2>/dev/null | head -20"
)

# ── Tier 3: 未対応見込み（MISS を正直に記録する）──────────────────────
# ここで出た MISS が次スプリントのバックログになる。良性かつ後始末込みで構成。
TIER3_TECHNIQUES=(
  # ORDER MATTERS: T1140 must run BEFORE T1027, and they are not interchangeable.
  # Both commands contain `base64 -d`, so both match the same rule
  # ("Base64 Obfuscation Command Execution (Linux)", tagged T1140). Alerts are
  # deduplicated on agent+rule-title for 5 minutes (alert_pipeline.go), so whichever
  # of the two runs SECOND produces no alert in its own scoring window and is scored
  # MISS — deterministically, not intermittently. With T1027 first, T1140 was a
  # "stable real gap" in four consecutive measurement rounds; the product had
  # detected it every time (T1140 alerts are in the DB), the measurement just could
  # not see it. Verified live: an identical command re-run 69s later produced 0 alerts.
  # T1140 first is the correct order because T1027 still earns its own credit from
  # `Decode Base64 Encoded Text` (a distinct T1027-tagged rule that T1140's command
  # does not trigger), whereas T1140 has no rule of its own that T1027 misses.
  "T1140|T3 deobfuscate/decode|-|echo 'YmVuaWdu' | base64 -d"
  "T1027|T3 obfuscated command (base64)|-|echo 'ZWNobyBiZW5pZ24=' | base64 -d | bash"
  "T1070.004|T3 indicator removal (file deletion)|-|f=\$(mktemp); echo x >\"\$f\"; rm -f \"\$f\""
  "T1222.002|T3 file permission modification|-|f=\$(mktemp); chmod 777 \"\$f\"; rm -f \"\$f\""
  "T1548.003|T3 sudo non-interactive|-|sudo -n true 2>/dev/null || true"
  "T1552.001|T3 credentials in files|-|grep -ril password /etc 2>/dev/null | head -3"
  "T1574.006|T3 LD_PRELOAD injection|-|LD_PRELOAD=/dev/shm/nonexistent-benign.so /bin/true 2>/dev/null || true"
  "T1105|T3 ingress tool transfer|-|curl -s -o /tmp/atomic-dl.bin http://localhost:8080/healthz 2>/dev/null; rm -f /tmp/atomic-dl.bin"
  "T1036.005|T3 masquerading as system binary|-|cp /bin/true /tmp/systemd-helper 2>/dev/null && /tmp/systemd-helper; rm -f /tmp/systemd-helper"
  # NOTE: deliberately NOT bash /dev/tcp. That idiom is itself a reverse-shell
  # signature, so a /dev/tcp sweep fires the reverse-shell rules and the run gets
  # scored on the wrong technique. A plain socket connect measures T1046 honestly.
  # Sweeps this host's own LAN address rather than loopback, because loopback
  # connections are not reported as network events.
  "T1046|T3 port sweep (socket connect)|-|python3 -c \"import socket,subprocess; ip=subprocess.run(['hostname','-I'],capture_output=True,text=True).stdout.split()[0]; [socket.socket().connect_ex((ip,p)) for p in range(8000,8021)]\""
)

# 選択されたティアを1本のリストに束ねる。
TECHNIQUES=()
case ",$TIERS," in *,1,*) TECHNIQUES+=("${TIER1_TECHNIQUES[@]}") ;; esac
case ",$TIERS," in *,2,*) TECHNIQUES+=("${TIER2_TECHNIQUES[@]}") ;; esac
case ",$TIERS," in *,3,*) TECHNIQUES+=("${TIER3_TECHNIQUES[@]}") ;; esac
if [ "${#TECHNIQUES[@]}" -eq 0 ]; then
  echo "TIERS='$TIERS' に該当するテクニックがありません (指定例: TIERS=\"1,2,3\")" >&2
  exit 1
fi

now_utc() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

# Refuse to run while another instance is writing the same runlog. A run takes
# tens of minutes, so it is easy to start a second one by accident (a re-paste, a
# forgotten background job) — and because both instances append to the same file,
# the result is not an error but a SILENTLY CORRUPT runlog: interleaved rows,
# techniques recorded twice, and a scorecard whose denominator is inflated. That
# happened live and produced an 84.4% reading against 32 "techniques" for a
# 22-technique run. mkdir is atomic, so it works without flock.
LOCK="${OUT}.lock"
if ! mkdir "$LOCK" 2>/dev/null; then
  echo "エラー: 別の実行が $OUT に書き込み中です (ロック: $LOCK)。" >&2
  echo "       完了を待つか、停止済みなら rmdir '$LOCK' で解除してください。" >&2
  exit 1
fi
trap 'rmdir "$LOCK" 2>/dev/null' EXIT

printf 'technique,test_name,start_utc,end_utc,exit_code,scenario\n' >"$OUT"

echo "実行ティア: $TIERS / テクニック数: ${#TECHNIQUES[@]} / 待機: 既定${SETTLE}s・探索群${DISCOVERY_PACE}s"

for entry in "${TECHNIQUES[@]}"; do
  IFS='|' read -r tech name pace cmd <<<"$entry"
  # "burst" = 探索群（相関に必要な密度で流す）。"-" = 既定の疎な間隔。
  case "$pace" in
    burst) wait_s="$DISCOVERY_PACE" ;;
    -|"")  wait_s="$SETTLE" ;;
    *)     wait_s="$pace" ;;
  esac
  echo "=== $tech ($name, +${wait_s}s) ==="
  start="$(now_utc)"
  bash -c "$cmd" >/dev/null 2>&1
  rc=$?
  sleep "$wait_s"
  end="$(now_utc)"
  printf '%s,%s,%s,%s,%s,%s\n' "$tech" "$name" "$start" "$end" "$rc" "$SCENARIO" >>"$OUT"
done

echo "runlog 出力: $OUT"

# Sanity-check the runlog before anyone scores it: one data row per technique,
# no duplicates. A mismatch means the file was written by more than one run (or
# truncated), and scoring it would report a number that looks plausible and is
# wrong — so say so here rather than let it through.
rows=$(($(wc -l <"$OUT") - 1))
dups=$(cut -d, -f1 "$OUT" | tail -n +2 | sort | uniq -d | tr '\n' ' ')
if [ "$rows" -ne "${#TECHNIQUES[@]}" ] || [ -n "$dups" ]; then
  echo "警告: runlog が不正です (行数=$rows, 期待=${#TECHNIQUES[@]}${dups:+, 重複=$dups})。" >&2
  echo "      同時実行や中断が疑われます。採点せず、測定をやり直してください。" >&2
  exit 2
fi

echo "採点: attack-scorer -server <URL> -token <TOKEN> -runlog $OUT"
echo "※ Tier3 の MISS は想定内。負債台帳(次スプリントのバックログ)として記録すること。"
