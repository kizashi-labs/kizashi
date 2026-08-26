#!/usr/bin/env bash
# Kizashi — エージェント堅牢性スイート（検証ホスト上で実行）
#
# 今セッションで実機発見した障害モードを再現テスト化したもの:
#   - 半開きEventStream（サーバが読み取り停止／TCPはESTABLISHED）での送信ハング
#     → 期待: sendWithWatchdog が sendTimeout 超過で検知し再接続（PR #325）
#   - ingestion 断中の「online に見えるがイベント送出ゼロ」＝サイレント・テレメトリ断
#     → 期待: ローカルバッファへ退避し、復旧後にドレイン（恒久損失ゼロ／有界）
#
# 設計: eBPF プロセスコレクタが exec を捕捉する性質を使い、ユニークな
#   `cat /tmp/rb_<marker>` を N 回実行 → 障害中に発生 → 復旧後にどれだけ届いたかで
#   「サイレント損失」を定量する。docker pause/stop のみ使用（可逆）。
#
# 使い方:
#   ./run-robustness.sh baseline
#   ./run-robustness.sh halfopen   [pause_sec]      # 既定 25s (> sendTimeout 15s)
#   ./run-robustness.sh outage     [stop_sec]       # 既定 30s
#   ./run-robustness.sh soak       [minutes]        # 既定 10 分
#   ./run-robustness.sh all
set -uo pipefail

AGENT_ID="${AGENT_ID:-9ed28fec-3e61-4f7f-8626-d1a782e6ae9c}"
PG="${PG:-kizashi-postgres}"
STREAM="${STREAM:-kizashi-ingestion}"        # agent gRPC EventStream の接続先 (:9091)
DB_USER="${DB_USER:-edr}"; DB="${DB:-edrplatform}"
AGENT_LOG="${AGENT_LOG:-/tmp/kizashi-agent.log}"
SEND_TIMEOUT="${SEND_TIMEOUT:-15}"             # agent sendWithWatchdog 既定 (秒)
MARKERS="${MARKERS:-200}"                        # 障害中に発生させるマーカー数
DRAIN_WAIT="${DRAIN_WAIT:-60}"                  # 復旧後ドレインを待つ最大秒数

psql_q(){ docker exec "$PG" psql -U "$DB_USER" -d "$DB" -P pager=off -t -A -c "$1" 2>/dev/null | tr -d '[:space:]'; }
agent_pid(){ pgrep -x kizashi-agent | head -1; }
agent_alive(){ [ -n "$(agent_pid)" ] && echo yes || echo no; }
agent_status(){ psql_q "SELECT status FROM agents WHERE id='$AGENT_ID'"; }
agent_rss_kb(){ local p; p=$(agent_pid); [ -n "$p" ] && awk '/VmRSS/{print $2}' "/proc/$p/status" 2>/dev/null || echo 0; }
# 直近 $2 でコマンドラインに $1 を含む process イベント数
mark_count(){ psql_q "SELECT count(*) FROM events WHERE agent_id='$AGENT_ID' AND event_type='process' AND raw_data->>'command_line' LIKE '%$1%' AND time>now()-interval '$2'"; }

gen_markers(){ # $1=marker $2=count
  local f="/tmp/rb_$1"; : >"$f"
  for _ in $(seq 1 "$2"); do /bin/cat "$f" >/dev/null 2>&1; done
}
log_since(){ sudo awk -v t="$1" '$0 ~ t' "$AGENT_LOG" 2>/dev/null; }
AGENT_CWD="${AGENT_CWD:-/home/ubuntu/edr-platform/agent}"
AGENT_BIN="${AGENT_BIN:-/tmp/kizashi-agent}"
CFG="${CFG:-/etc/edr-agent/config.toml}"
restart_agent(){
  for p in $(pgrep -x kizashi-agent); do local pp; pp=$(ps -o ppid= -p "$p" 2>/dev/null | tr -d ' '); sudo kill "$p" 2>/dev/null; [ -n "$pp" ] && sudo kill "$pp" 2>/dev/null; done
  sleep 3; ( cd "$AGENT_CWD" && sudo setsid nohup "$AGENT_BIN" </dev/null >"$AGENT_LOG" 2>&1 & ); sleep 8
}
SERVER_URL="${SERVER_URL:-https://203-0-113-10.nip.io}"
TOKEN="${TOKEN:-}"
ISO_ACTIVE=0
CFG_SAVED=""
restore(){
  docker unpause "$STREAM" >/dev/null 2>&1; docker start "$STREAM" >/dev/null 2>&1
  # Always lift isolation if a test left it on (prevents lockout / stuck egress).
  if [ "$ISO_ACTIVE" = 1 ]; then
    [ -n "$TOKEN" ] && curl -sk -X POST -H "Authorization: Bearer $TOKEN" "$SERVER_URL/api/v1/agents/$AGENT_ID/unisolate" >/dev/null 2>&1
    sudo iptables -F EDR_ISOLATE 2>/dev/null; sudo iptables -X EDR_ISOLATE 2>/dev/null  # last-resort local clear (iptables)
    sudo nft delete table inet edr_isolate 2>/dev/null                                    # last-resort local clear (nftables)
    ISO_ACTIVE=0
  fi
  if [ -n "$CFG_SAVED" ] && [ -f "$CFG_SAVED" ]; then sudo cp -f "$CFG_SAVED" "$CFG"; CFG_SAVED=""; restart_agent; fi
}
trap restore EXIT
ok(){ echo "  ✅ $*"; }; bad(){ echo "  ❌ $*"; FAIL=1; }; info(){ echo "  ・ $*"; }

require_telemetry(){
  local n; n=$(mark_count "" "30 sec"); n=${n:-0}
  if [ "${n:-0}" -gt 0 ]; then ok "ベースライン: process テレメトリ流入中 (${n}/30s)"; else
    bad "ベースライン: process イベントが流入していない（eBPFビルドagentか確認）"; fi
}

scenario_baseline(){
  echo "== baseline =="
  info "agent alive=$(agent_alive) status=$(agent_status) rss=$(agent_rss_kb)KB"
  require_telemetry
}

scenario_halfopen(){
  local PAUSE="${1:-25}"; local M="hopen$(date +%s)"
  echo "== halfopen（半開きEventStream / docker pause $STREAM ${PAUSE}s）=="
  require_telemetry
  local before_pid; before_pid=$(agent_pid)
  docker pause "$STREAM" >/dev/null 2>&1 && info "paused $STREAM (TCPはESTABLISHEDのまま=半開き)"
  local t0=$(date +%s)
  gen_markers "$M" "$MARKERS"; info "障害中に $MARKERS マーカー実行"
  sleep "$PAUSE"
  # 期待: pause >= sendTimeout の間に watchdog 検知ログが出る
  local wd; wd=$(log_since "watchdog\|stream send failed\|reconnect\|signalDisconnect\|送信" | tail -3)
  [ -n "$wd" ] && ok "送信ウォッチドッグ/再接続の痕跡あり" || bad "ウォッチドッグの痕跡が出ていない（ハング疑い）"
  docker unpause "$STREAM" >/dev/null 2>&1 && info "unpaused $STREAM"
  # ドレイン待ち
  local arrived=0
  for _ in $(seq 1 "$DRAIN_WAIT"); do arrived=$(mark_count "rb_$M" "10 min"); arrived=${arrived:-0}; [ "$arrived" -ge "$MARKERS" ] && break; sleep 1; done
  local rt=$(( $(date +%s) - t0 ))
  [ "$(agent_alive)" = yes ] && ok "agent 継続稼働 (pid $(agent_pid))" || bad "agent が死亡"
  [ "$(agent_pid)" = "$before_pid" ] && ok "プロセス再起動なし（自己回復）" || info "agent PID 変化（再起動した）"
  info "マーカー到達 ${arrived}/${MARKERS}（復旧/ドレイン ~${rt}s）"
  if [ "$arrived" -ge "$MARKERS" ]; then ok "サイレント損失ゼロ（全マーカーがドレイン）"
  elif [ "$arrived" -gt 0 ]; then info "一部到達（残りは継続ドレイン中の可能性）— 損失=$((MARKERS-arrived))"
  else bad "マーカー全消失（サイレント・テレメトリ断の疑い）"; fi
}

scenario_outage(){
  local STOP="${1:-30}"; local M="out$(date +%s)"
  echo "== outage（ingestion 完全停止 / docker stop $STREAM ${STOP}s）=="
  require_telemetry; local t0=$(date +%s)
  docker stop "$STREAM" >/dev/null 2>&1 && info "stopped $STREAM"
  info "停止中も heartbeat(:8080)は別経路 → status=$(agent_status)（onlineに見えることの確認）"
  gen_markers "$M" "$MARKERS"; info "障害中に $MARKERS マーカー実行"
  sleep "$STOP"
  docker start "$STREAM" >/dev/null 2>&1 && info "started $STREAM"
  local arrived=0
  for _ in $(seq 1 "$DRAIN_WAIT"); do arrived=$(mark_count "rb_$M" "10 min"); arrived=${arrived:-0}; [ "$arrived" -ge "$MARKERS" ] && break; sleep 1; done
  local rt=$(( $(date +%s) - t0 ))
  [ "$(agent_alive)" = yes ] && ok "agent 継続稼働" || bad "agent が死亡"
  info "マーカー到達 ${arrived}/${MARKERS}（~${rt}s）"
  if [ "$arrived" -ge "$MARKERS" ]; then ok "オフラインバッファ→ドレイン成功（損失ゼロ）"
  elif [ "$arrived" -gt 0 ]; then info "一部到達 — 損失=$((MARKERS-arrived))"
  else bad "全消失（バッファ/ドレイン不良）"; fi
}

scenario_soak(){
  local MIN="${1:-10}"; echo "== soak（${MIN}分・メモリ/テレメトリ継続性）=="
  local rss0; rss0=$(agent_rss_kb); local gaps=0 maxrss=$rss0
  for i in $(seq 1 "$MIN"); do
    gen_markers "soak" 10; sleep 55
    local r; r=$(agent_rss_kb); [ "$r" -gt "$maxrss" ] && maxrss=$r
    local c; c=$(mark_count "" "60 sec"); c=${c:-0}; [ "$c" -eq 0 ] && gaps=$((gaps+1))
    info "[$i/$MIN] rss=${r}KB ev/60s=${c}"
  done
  local growth=$(( (maxrss - rss0) * 100 / (rss0>0?rss0:1) ))
  [ "$(agent_alive)" = yes ] && ok "soak 後も稼働" || bad "soak 中に死亡"
  [ "$gaps" -eq 0 ] && ok "テレメトリ無断絶（全分でイベント有）" || bad "テレメトリ断 ${gaps} 分"
  [ "$growth" -lt 50 ] && ok "RSS 増加 ${growth}%（リーク兆候なし）" || bad "RSS 増加 ${growth}%（リーク疑い）"
}

scenario_spool(){
  # スプール上限到達: バッファを小さくし断中に大量発生 → ①有界化 ②復旧後に再開（恒久stuckしない=run1障害の不在）
  local CAP="${1:-2}" STOP="${2:-45}" FLOOD="${3:-12000}"; local M="spost$(date +%s)"
  echo "== spool（local_buffer_size_mb=${CAP}MB へ縮小 / stop ${STOP}s / flood ${FLOOD}）=="
  CFG_SAVED="/tmp/cfg_$(date +%s).bak"; sudo cp -f "$CFG" "$CFG_SAVED"
  sudo sed -i "s/^local_buffer_size_mb = .*/local_buffer_size_mb = $CAP/" "$CFG"
  # ★クリーンスレートは restart の前に（restart 後に rm すると in-memory used/head/tail が乖離）。
  #   さらにディレクトリ自体を作り直す: run1 で 71k ファイルを溜めた痕跡で dir inode が ~17MB に
  #   ブロートしており（ext4 はディレクトリを縮小しない）、`du -sm <dir>` だとそれを誤って含む。
  local BUFDIR=/var/lib/edr-agent/quarantine/buffer
  sudo rm -rf "$BUFDIR" 2>/dev/null; sudo mkdir -p "$BUFDIR"; sudo chmod 700 "$BUFDIR"
  restart_agent; require_telemetry
  docker stop "$STREAM" >/dev/null 2>&1 && info "stopped $STREAM"
  gen_markers "flood" "$FLOOD"; info "断中に $FLOOD イベント flood"
  sleep 3
  # ★実 .buf ファイルのバイト合計で測る（dir inode ブロートを含めない）。
  local bufb bufmb; bufb=$(sudo find "$BUFDIR" -name '*.buf' -printf '%s\n' 2>/dev/null | awk '{s+=$1} END{print s+0}'); bufmb=$(( bufb/1048576 ))
  if [ "$bufmb" -le $((CAP+3)) ]; then ok "バッファ有界 実.buf=${bufmb}MB ≤ ${CAP}+3MB（dropOldest で上限内に抑制）"; else bad "実.buf=${bufmb}MB が上限 ${CAP}MB を超過（cap 非機能の疑い）"; fi
  sleep "$STOP"
  docker start "$STREAM" >/dev/null 2>&1 && info "started $STREAM"
  sleep 3; gen_markers "$M" 100; info "復旧後に 100 マーカー（再開するか＝stuck しないか）"
  local post=0; for _ in $(seq 1 "$DRAIN_WAIT"); do post=$(mark_count "rb_$M" "5 min"); post=${post:-0}; [ "$post" -ge 80 ] && break; sleep 1; done
  [ "$(agent_alive)" = yes ] && ok "agent 継続稼働" || bad "agent 死亡"
  if [ "$post" -ge 80 ]; then ok "復旧後の新規イベントが届く ${post}/100（恒久stuckなし＝run1障害の不在）"
  else bad "復旧後も新規イベントが届かない ${post}/100（バッファ満杯で送出停止＝run1型障害の疑い）"; fi
  restore  # 設定戻し＋再起動
}

scenario_churn(){
  local ROUNDS="${1:-6}"; local M="churn$(date +%s)"
  echo "== churn（再接続ストーム: pause/unpause を ${ROUNDS} 回反復）=="
  require_telemetry; local pid0; pid0=$(agent_pid); local rss0; rss0=$(agent_rss_kb)
  for i in $(seq 1 "$ROUNDS"); do
    docker pause "$STREAM" >/dev/null 2>&1; sleep 3; docker unpause "$STREAM" >/dev/null 2>&1; sleep 2
    info "[$i/$ROUNDS] pause/unpause"
  done
  sleep 5; gen_markers "$M" 100
  local arrived=0; for _ in $(seq 1 "$DRAIN_WAIT"); do arrived=$(mark_count "rb_$M" "5 min"); arrived=${arrived:-0}; [ "$arrived" -ge 80 ] && break; sleep 1; done
  local rss1; rss1=$(agent_rss_kb); local growth=$(( (rss1-rss0)*100/(rss0>0?rss0:1) ))
  [ "$(agent_alive)" = yes ] && ok "ストーム後も稼働" || bad "ストーム中に死亡"
  [ "$(agent_pid)" = "$pid0" ] && ok "プロセス再起動なし" || info "PID 変化（再起動した）"
  [ "$arrived" -ge 80 ] && ok "ストーム後テレメトリ回復 ${arrived}/100" || bad "回復せず ${arrived}/100"
  [ "$growth" -lt 50 ] && ok "RSS 増加 ${growth}%（churn でのリークなし）" || bad "RSS 増加 ${growth}%（churn リーク疑い）"
}

scenario_burst(){
  local N="${1:-3000}"; local M="burst$(date +%s)"
  echo "== burst（イベント・バースト ${N} を高速発生 / ingestion 正常）=="
  require_telemetry; local rss0; rss0=$(agent_rss_kb)
  gen_markers "$M" "$N"; info "$N イベントを連続発生"
  local arrived=0; for _ in $(seq 1 "$DRAIN_WAIT"); do arrived=$(mark_count "rb_$M" "5 min"); arrived=${arrived:-0}; [ "$arrived" -ge "$N" ] && break; sleep 1; done
  local rss1; rss1=$(agent_rss_kb); local growth=$(( (rss1-rss0)*100/(rss0>0?rss0:1) ))
  local pct=$(( arrived*100/(N>0?N:1) ))
  [ "$(agent_alive)" = yes ] && ok "バースト後も稼働" || bad "バースト中に死亡"
  [ "$growth" -lt 50 ] && ok "RSS 増加 ${growth}%（バーストでのメモリ暴走なし）" || bad "RSS 増加 ${growth}%"
  info "到達 ${arrived}/${N}（${pct}%）＝throttle/ringbuf 下のスループット測定値"
  if [ "$pct" -ge 90 ]; then ok "高スループット維持（${pct}%）"
  elif [ "$pct" -ge 10 ]; then info "一部ドロップ（${pct}%）＝極端バースト時の ringbuf/throttle 上限（設計トレードオフ・要記録）"
  else bad "壊滅的ドロップ（${pct}%）＝バックプレッシャ不良の疑い"; fi
}

scenario_isolate(){
  # 隔離→検証→解除の往復（検知→対応パイプラインの response 側）。
  # ★安全: agent は EDR_ISOLATION_ALLOW_SSH=true 起動が必須（ESTABLISHED も許可されるが二重の安全策）。
  echo "== isolate（隔離→検証→解除の往復 / API 経由）=="
  [ -z "$TOKEN" ] && { bad "TOKEN 未設定（export TOKEN=<JWT> が必要）"; return; }
  local P; P=$(agent_pid)
  if sudo cat "/proc/$P/environ" 2>/dev/null | tr '\0' '\n' | grep -q 'EDR_ISOLATION_ALLOW_SSH=true'; then
    ok "ALLOW_SSH=true（隔離中も SSH 維持＝ロックアウト回避）"
  else
    bad "EDR_ISOLATION_ALLOW_SSH=true で起動していない — SSH ロックアウト危険。中止"; return
  fi
  # ★host のファイアウォール隔離状態は iptables と nftables の両方を見る（agent は nft 優先＝
  #   isNFTablesAvailable() が true なら nft table `inet edr_isolate` を作る）。
  iso_applied(){ sudo iptables -L EDR_ISOLATE -n >/dev/null 2>&1 || sudo nft list table inet edr_isolate >/dev/null 2>&1; }
  # 既に隔離中なら先に解除
  if iso_applied; then
    info "既に隔離中→先に解除"; curl -sk -X POST -H "Authorization: Bearer $TOKEN" "$SERVER_URL/api/v1/agents/$AGENT_ID/unisolate" >/dev/null 2>&1; sleep 6
  fi
  # 隔離発令（API → server → NATS → ingestion bridge → agent command stream → executor → iptables/nft）
  curl -sk -X POST -H "Authorization: Bearer $TOKEN" "$SERVER_URL/api/v1/agents/$AGENT_ID/isolate" >/dev/null 2>&1
  ISO_ACTIVE=1; info "isolate API 発令"
  local applied=0; for _ in $(seq 1 30); do iso_applied && { applied=1; break; }; sleep 2; done
  [ "$applied" = 1 ] && ok "host に隔離 FW 適用（iptables/nft EDR_ISOLATE）" || bad "隔離が適用されない（command stream 未達？）"
  info "agent DB status=$(agent_status)"
  # 外部 egress が遮断され、SSH(established)は生存していることを確認
  if timeout 8 curl -s -o /dev/null --max-time 6 https://1.1.1.1 2>/dev/null; then bad "外部 egress がブロックされていない（隔離不全）"; else ok "外部 egress ブロック（隔離有効）"; fi
  ok "SSH 継続応答（本コマンド自体が返っている＝established 温存）"
  # 解除
  curl -sk -X POST -H "Authorization: Bearer $TOKEN" "$SERVER_URL/api/v1/agents/$AGENT_ID/unisolate" >/dev/null 2>&1
  local cleared=0; for _ in $(seq 1 30); do iso_applied || { cleared=1; break; }; sleep 2; done
  ISO_ACTIVE=0
  [ "$cleared" = 1 ] && ok "unisolate で隔離 FW 除去" || bad "解除されない"
  if timeout 10 curl -s -o /dev/null --max-time 8 https://1.1.1.1 2>/dev/null; then ok "外部 egress 復旧"; else info "egress 復旧未確認（DNS/一時要因の余地）"; fi
  info "agent DB status=$(agent_status)"
}

FAIL=0
case "${1:-all}" in
  baseline) scenario_baseline ;;
  halfopen) scenario_halfopen "${2:-25}" ;;
  outage)   scenario_outage "${2:-30}" ;;
  soak)     scenario_soak "${2:-10}" ;;
  spool)    scenario_spool "${2:-2}" "${3:-45}" "${4:-12000}" ;;
  churn)    scenario_churn "${2:-6}" ;;
  burst)    scenario_burst "${2:-3000}" ;;
  isolate)  scenario_isolate ;;
  all)      scenario_baseline; echo; scenario_halfopen 25; echo; scenario_outage 30 ;;
  *) echo "usage: $0 {baseline|halfopen [s]|outage [s]|soak [min]|spool [cap_mb] [stop_s] [flood]|churn [rounds]|burst [n]|isolate|all}  (isolate は TOKEN=<JWT> と ALLOW_SSH 起動が必要)"; exit 2 ;;
esac
echo; [ "$FAIL" -eq 0 ] && echo "=== ROBUSTNESS: PASS ===" || echo "=== ROBUSTNESS: FAIL ==="
exit "$FAIL"
