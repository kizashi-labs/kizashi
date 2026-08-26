#!/usr/bin/env bash
# measure-persistence-beacon.sh — 2026-07 の検知深化(FIM /home 永続化・migration 311
# file_event ルール・調和折り畳みビーコン検出)を実機で検証するための安全バッテリ。
#
# run-atomics.sh(discovery/execution 中心)を補完し、本スクリプトは:
#   ① 永続化ファイル書き込み(FIM file_event 経路) — authorized_keys/.bashrc/
#      ld.so.preload/rc.local/cron。SHA-256 ポーリング FIM(既定60s)を待って発火させ、
#      **必ずリバート**する。
#   ② ジッタ入り周期ビーコン(調和折り畳みビーコン検出) — 固定外部IPへ ~N回の周期接続。
#   ③ 資格情報アクセス(T1003.008 /etc/shadow 読取)。
#
# 出力は attack-scorer 互換の runlog CSV(technique,test_name,start_utc,end_utc,exit_code,scenario)。
#
#   使い方: sudo ./measure-persistence-beacon.sh [out.csv]
#   採点  : attack-scorer -server <URL> -token <JWT> -runlog out.csv
#
# ⚠ 隔離された使い捨て検証 endpoint でのみ実行すること(system ファイルを一時改変する)。
#    全変更は本スクリプトが元へ戻すが、共有/本番ホストでは絶対に実行しない。
#    docs/ops/検知率能動計測ランブック.md を必ず参照。
set -u

OUT="${1:-persistence-beacon-runlog.csv}"
SCENARIO="${SCENARIO:-persistence_beacon}"
FIM_WAIT="${FIM_WAIT:-70}"          # FIM ポーリング(既定60s)+余裕。migration 反映済み前提。
BEACON_COUNT="${BEACON_COUNT:-10}"  # ビーコン接続回数(MinEvents=8 以上)
BEACON_BASE="${BEACON_BASE:-40}"    # ビーコン基本周期(秒, MinInterval=10s 以上)
BEACON_DST="${BEACON_DST:-1.1.1.1}" # 固定外部IP(same-dst 集約のため。EDRサーバ宛は無効)
TEST_USER="${TEST_USER:-fimprobe}"

now_utc() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
log()     { printf '[%s] %s\n' "$(now_utc)" "$*" >&2; }

# emit TECH NAME START END RC — 1レコードを runlog に追記。
emit() { printf '%s,%s,%s,%s,%s,%s\n' "$1" "$2" "$3" "$4" "${5:-0}" "$SCENARIO" >>"$OUT"; }

if [[ $EUID -ne 0 ]]; then
  log "root で実行してください(system ファイル改変のため)。sudo $0"
  exit 1
fi

printf 'technique,test_name,start_utc,end_utc,exit_code,scenario\n' >"$OUT"
log "runlog: $OUT / FIM_WAIT=${FIM_WAIT}s / beacon=${BEACON_COUNT}x@${BEACON_BASE}s→${BEACON_DST}"

# ── ① 永続化ファイル書き込み(FIM file_event) ────────────────────────────
# 各技法: 書込 → FIM ポーリングを待つ → リバート。start/end はイベントが乗る窓。

# T1098.004 SSH authorized_keys (regular user home)
run_authorized_keys() {
  local home="/home/${TEST_USER}"
  useradd -m -s /bin/bash "${TEST_USER}" 2>/dev/null || true
  install -d -m700 -o "${TEST_USER}" -g "${TEST_USER}" "${home}/.ssh" 2>/dev/null || true
  local start end; start="$(now_utc)"
  echo 'ssh-ed25519 AAAAC3NzaC1lZDI1 attacker@probe' >>"${home}/.ssh/authorized_keys"
  sleep "$FIM_WAIT"; end="$(now_utc)"
  rm -f "${home}/.ssh/authorized_keys"
  emit "T1098.004" "authorized_keys_write" "$start" "$end" 0
}

# T1546.004 shell init (.bashrc)
run_bashrc() {
  local start end f="/home/${TEST_USER}/.bashrc"; touch "$f"
  start="$(now_utc)"
  echo '# edr-probe: benign marker' >>"$f"
  sleep "$FIM_WAIT"; end="$(now_utc)"
  sed -i '/edr-probe: benign marker/d' "$f"
  emit "T1546.004" "bashrc_append" "$start" "$end" 0
}

# T1574.006 ld.so.preload — 存在しない .so を書いてすぐ消す(実際にはpreloadさせない)
run_ldso_preload() {
  local start end f="/etc/ld.so.preload" bak=""
  [[ -f "$f" ]] && { bak="$(mktemp)"; cp -a "$f" "$bak"; }
  start="$(now_utc)"
  echo '/opt/edr-probe-nonexistent.so' >"$f"   # 実体無し=どのプロセスにもロードされない
  sleep "$FIM_WAIT"; end="$(now_utc)"
  if [[ -n "$bak" ]]; then mv "$bak" "$f"; else rm -f "$f"; fi
  emit "T1574.006" "ldso_preload_write" "$start" "$end" 0
}

# T1037.004 rc.local
run_rc_local() {
  local start end f="/etc/rc.local" bak=""
  [[ -f "$f" ]] && { bak="$(mktemp)"; cp -a "$f" "$bak"; }
  start="$(now_utc)"
  printf '#!/bin/sh\n# edr-probe benign\nexit 0\n' >"$f"
  sleep "$FIM_WAIT"; end="$(now_utc)"
  if [[ -n "$bak" ]]; then mv "$bak" "$f"; else rm -f "$f"; fi
  emit "T1037.004" "rc_local_write" "$start" "$end" 0
}

# T1053.003 cron drop-in
run_cron_dropin() {
  local start end f="/etc/cron.d/edr-probe"
  start="$(now_utc)"
  printf '# edr-probe benign\n* * * * * root /bin/true\n' >"$f"
  sleep "$FIM_WAIT"; end="$(now_utc)"
  rm -f "$f"
  emit "T1053.003" "cron_dropin_write" "$start" "$end" 0
}

# ── ② ジッタ入り周期ビーコン(調和折り畳み) ───────────────────────────────
run_beacon() {
  local start end; start="$(now_utc)"
  log "beacon: ${BEACON_COUNT} 回 ~${BEACON_BASE}s±25% ジッタ → ${BEACON_DST}:443"
  local i jitter sleep_s
  for ((i=1;i<=BEACON_COUNT;i++)); do
    # 決定的な擬似ジッタ(±25%): base * (0.75 + 0.5*((i*7)%10)/10)
    jitter=$(( (i*7)%10 ))
    sleep_s=$(( BEACON_BASE * (75 + 5*jitter) / 100 ))
    # 外部IPへTCP接続(実データ送受は最小)。curl 不在時は /dev/tcp フォールバック。
    if command -v curl >/dev/null; then
      curl -s -o /dev/null --max-time 4 "https://${BEACON_DST}/" 2>/dev/null || true
    else
      timeout 4 bash -c "echo >/dev/tcp/${BEACON_DST}/443" 2>/dev/null || true
    fi
    log "  beacon $i/${BEACON_COUNT} → next in ${sleep_s}s"
    (( i < BEACON_COUNT )) && sleep "$sleep_s"
  done
  end="$(now_utc)"
  emit "T1071" "jittered_beacon" "$start" "$end" 0
}

# ── ③ 資格情報アクセス ───────────────────────────────────────────────────
run_shadow_read() {
  local start end; start="$(now_utc)"
  cat /etc/shadow >/dev/null 2>&1 || true
  sleep 5; end="$(now_utc)"
  emit "T1003.008" "shadow_read" "$start" "$end" 0
}

trap 'log "中断: クリーンアップ実行"; rm -f /etc/cron.d/edr-probe; userdel -r "${TEST_USER}" 2>/dev/null || true' INT TERM

log "── ① 永続化 FIM ─────────────"
run_authorized_keys
run_bashrc
run_ldso_preload
run_rc_local
run_cron_dropin
log "── ③ 資格情報 ───────────────"
run_shadow_read
log "── ② ビーコン(最長 ~$((BEACON_COUNT*BEACON_BASE))s) ─"
run_beacon

# 後始末(冪等)
userdel -r "${TEST_USER}" 2>/dev/null || true

log "完了。runlog: $OUT"
log "採点: attack-scorer -server <URL> -token <JWT> -runlog $OUT"
