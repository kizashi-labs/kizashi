#!/usr/bin/env bash
# EDR-Agent エンドポイント可視性 実機検証スクリプト (Linux)。
#
# インストール済みエージェントの稼働状態・収集経路を確認し、既知の活動
# (一意なプロセス起動 / DNS解決 / TCP接続) を発生させる。出力(と、サーバ
# コンソールで marker が見えたか)を貼り戻してください。
#
# 注意: 出荷ビルド(ebpfタグ無し)の Linux プロセス監視は /proc ポーリングです
# (eBPF は現状ビルド不可のため未稼働)。本スクリプトは「ポーリング経路が実際に
# 動いてイベントをサーバへ転送しているか」の確認が主目的です。
#
# root で実行してください:  sudo bash verify-linux.sh
set -u
sep() { printf '\n%s\n== %s\n%s\n' "======================================================================" "$1" "======================================================================"; }

sep "0. 実行コンテキスト"
echo "whoami   : $(whoami)"
echo "hostname : $(hostname)"
echo "kernel   : $(uname -r)"
[ -r /etc/os-release ] && . /etc/os-release && echo "os       : ${PRETTY_NAME:-unknown}"
[ "$(id -u)" -ne 0 ] && echo "WARN: root ではありません。一部の確認が制限されます (sudo 推奨)。"

sep "1. エージェント/ウォッチドッグ サービス状態"
if command -v systemctl >/dev/null 2>&1; then
  systemctl status edr-watchdog --no-pager 2>/dev/null | head -12 || echo "edr-watchdog.service が見つかりません"
fi
echo "プロセス:"
ps -eo pid,comm,rss,etime | grep -E 'edr-agent|edr-watchdog' | grep -v grep || echo "  (エージェントプロセスが見つかりません)"

sep "2. エージェントログ — コレクタ起動とエラー"
LOG=/var/log/edr-agent/agent.log
if [ -r "$LOG" ]; then
  echo "ログ: $LOG"
  echo "--- 収集/監視 関連 (最新15件) ---"
  grep -aiE 'collector|monitor|開始|started|ebpf|proc|enroll|connect' "$LOG" | tail -15
  echo "--- エラー/警告 (最新10件) ---"
  grep -aE '"level":"(ERROR|WARN)"' "$LOG" | tail -10
else
  echo "ログが読めません: $LOG (権限不足か別パス。journalctl -u edr-watchdog も試してください)"
  command -v journalctl >/dev/null 2>&1 && journalctl -u edr-watchdog --no-pager 2>/dev/null | tail -15
fi

sep "3. eBPF 状態の確認 (出荷ビルドは未稼働=想定どおり)"
if command -v bpftool >/dev/null 2>&1; then
  echo "ロード済みBPFプログラム数: $(bpftool prog show 2>/dev/null | grep -c 'tracepoint\|kprobe\|raw_tracepoint' || echo 0)"
else
  echo "bpftool 無し。/sys/kernel/btf/vmlinux 存在: $([ -e /sys/kernel/btf/vmlinux ] && echo yes || echo no)"
fi
echo "→ エージェント由来のBPFプログラムは通常 0 件 (eBPF経路はビルド未完成のため)。プロセス監視は /proc ポーリング。"

sep "4. 既知の活動を生成 (marker)"
TS=$(date +%s)
MARKER="edrverify_${TS}"
DOMAIN="edrverify-${TS}.example.com"
echo "marker process : $MARKER (sleep 2 でラップ)"
( exec -a "$MARKER" sleep 2 ) &  # プロセス名を marker に
SLEEP_PID=$!
echo "marker DNS     : $DOMAIN を解決"
getent hosts "$DOMAIN" >/dev/null 2>&1 || nslookup "$DOMAIN" >/dev/null 2>&1 || true
echo "marker conn    : 1.1.1.1:443 へ接続試行"
(exec 3<>/dev/tcp/1.1.1.1/443) 2>/dev/null && echo "  接続OK" && exec 3>&- || echo "  接続不可(オフライン?)"
wait $SLEEP_PID 2>/dev/null
echo "活動生成 完了。"

sep "完了 / 次の確認"
cat <<EOF
このスクリプトはエンドポイント側で「活動を発生させた」ところまでです。
それがEDRに届いたかは、EDRサーバのコンソールで以下を検索して確認してください:
  - プロセスイベントに「${MARKER}」が出るか
  - DNSイベントに「${DOMAIN}」が出るか
  - ネットワークイベントに 1.1.1.1:443 への接続が出るか
上記セクション(0〜4)の出力をそのまま貼り戻してください。
EOF
