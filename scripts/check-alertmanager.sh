#!/usr/bin/env bash
# 本物の Alertmanager に deploy/alertmanager.yml を読ませて、
# **通知が実際に届くこと**を確かめます。
#
#   scripts/check-alertmanager.sh
#
# 終了コード:
#   0  確かめた
#   1  確かめて、問題が見つかった
#   2  **確かめられなかった** (Alertmanager を取ってこられない、など)
#
# 2 を 1 と分けてあるのは、`server/scripts/run_tests.sh` が
# 「落ちた」と「走らなかった」を別に数えるためです。**走らなかったことが
# 通ったことと同じ行になるのが、このキャンペーンが直してきた形です。**
#
# **構造検査（check_prometheus_rules.py）とは別のことを見ています。**
# あちらは「route が指す receiver が実在するか」「秘密が直書きされて
# いないか」を YAML として見ます。フィールド名が Alertmanager のスキーマに
# 合っているかは、**起動して初めて分かります。** 設定ファイル自身に
# 「本物の Alertmanager に読ませていません」と書いてありました。
#
# 確かめるのは3つ:
#   1. 本物の amtool が設定を受け付けること
#   2. 発火したアラートが receiver まで**届く**こと（runbook_url ごと）
#   3. inhibit_rules が実際に**抑制する**こと
#
# 秘密はダミーです。Slack にも PagerDuty にも送りません ——
# 宛先はこのスクリプトが立てるローカルの受け口に差し替えます。
set -euo pipefail

VERSION=${ALERTMANAGER_VERSION:-0.27.0}
WORK=${WORK:-/tmp/am-check}
# REPO は差し替えられます。**検査そのものを検査するため**です ——
# 壊れた設定を渡したときに終了コード 1 で戻ることは、正しい設定でしか
# 走らせられないと確かめようがありません（scripts/check_alertmanager_test.py）。
REPO=${REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
BIN="$WORK/alertmanager-$VERSION.linux-amd64"

say() { echo "$*" >&2; }

# pkill は使いません。**`pkill -f "alertmanager --config"` は、その文字列を
# 含む呼び出し元のシェル自身に当たります。** 実際に当たって、スクリプトを
# 書いている途中のシェルごと落ちました。PID を持っておいて、それだけ止めます。
AM_PID=""
SINK_PID=""
cleanup() {
  [ -n "$AM_PID" ] && kill "$AM_PID" 2>/dev/null || true
  [ -n "$SINK_PID" ] && kill "$SINK_PID" 2>/dev/null || true
  # **待たずに戻ると、9093 を掴んだまま次の起動が始まります。**
  # このスクリプトは検査自身の検査 (check_alertmanager_test.py) から
  # 続けて何度も呼ばれます。前の Alertmanager が終わりきる前に次が
  # 起動すると、bind に失敗した新しい方が黙って死に、`/-/ready` には
  # **古い方**が答え、その直後に古い方も終わって POST が接続できません。
  # 症状は「抑制していません」—— 設定の問題に見えます。
  [ -n "$AM_PID" ] && wait "$AM_PID" 2>/dev/null || true
  [ -n "$SINK_PID" ] && wait "$SINK_PID" 2>/dev/null || true
}
trap cleanup EXIT

# **確かめられなかったことを、確かめた結果として報告しない。**
# POST が失敗するのは設定のせいではありません。exit 2 は
# 「走らなかった」の側です（このファイル冒頭の約束）。
post_alerts() {
  if ! curl -sS -XPOST http://127.0.0.1:9093/api/v2/alerts \
       -H 'Content-Type: application/json' -d "$1" >/dev/null; then
    say "!! Alertmanager にアラートを渡せませんでした。**設定の問題ではありません**"
    [ -f "$WORK/am.log" ] && cat "$WORK/am.log" >&2 || true
    exit 2
  fi
}

mkdir -p "$WORK/secrets"
if [ ! -x "$BIN/alertmanager" ]; then
  say "== Alertmanager $VERSION を取得します"
  # **取ってこられないことは「確かめた」ではありません。** ネットワークが
  # 無い環境では終了コード 2 で戻り、呼び出し側がそれを数えます。
  #
  # `-f` が要ります。**無いと、404 の本文をファイルに書いて成功で戻ります。**
  # そのあと tar が落ちるので気づけはしますが、報告される理由が
  # 「展開できません」になり、原因（取得できていない）から離れます。
  if ! curl -fsSL --max-time 120 -o "$WORK/am.tgz" \
    "https://github.com/prometheus/alertmanager/releases/download/v$VERSION/alertmanager-$VERSION.linux-amd64.tar.gz"; then
    say "!! Alertmanager を取得できません（ネットワーク）。確かめられませんでした"
    exit 2
  fi
  if ! tar xzf "$WORK/am.tgz" -C "$WORK"; then
    say "!! 取得したアーカイブを展開できません。確かめられませんでした"
    exit 2
  fi
fi
if [ ! -x "$BIN/alertmanager" ] || [ ! -x "$BIN/amtool" ]; then
  say "!! Alertmanager のバイナリがありません。確かめられませんでした"
  exit 2
fi

# ダミーの秘密。**本物は要りません** —— 宛先を差し替えるので、
# 外に出る通信は起きません。
echo "https://hooks.slack.com/services/T00/B00/DUMMY" > "$WORK/secrets/slack_webhook_url"
echo "0123456789abcdef0123456789abcdef" > "$WORK/secrets/pagerduty_key"

# 出荷する設定はそのまま amtool に読ませます（下の 1.）。**届くかどうかを
# 試す方の写しだけ、宛先と group_wait を差し替えます。**
#
# group_wait を差し替えるのは、出荷値が 30s だからです。そのまま待つと
# この検査だけで30秒かかり、**遅い検査は走らせなくなります。**
# 出荷値が 30s のままであることは、差し替える前にここで確かめます ——
# 確かめずに書き換えると、**出荷値が変わったことに気づけません。**
python3 - "$REPO/deploy/alertmanager.yml" "$WORK/alertmanager.yml" "$WORK/secrets" <<'PY'
import sys
src, dst, secrets = sys.argv[1], sys.argv[2], sys.argv[3]
s = open(src).read()

if 'group_wait: 30s' not in s:
    raise SystemExit(
        "出荷する group_wait が 30s ではなくなっています。"
        "**この検査は 30s を 1s に差し替えて速くしています** —— "
        "値が変わったなら、差し替え先もここも見直してください")

s = s.replace('/etc/alertmanager/secrets', secrets)
s = s.replace('group_wait: 30s', 'group_wait: 1s', 1)
s = s.replace("  receiver: 'edr-slack'", "  receiver: 'local-sink'", 1)
s = s.rstrip() + """

  - name: 'local-sink'
    webhook_configs:
      - url: 'http://127.0.0.1:9099/hook'
        send_resolved: true
"""
open(dst, 'w').write(s)
PY

say "== 1. 設定を本物の amtool に読ませます"
# **出荷するファイルそのものを読ませます。** 写しだけを検査すると、
# 出荷値の書き間違いが素通りします。秘密のファイルが無くても
# check-config は通るので、置き換えは要りません。
"$BIN/amtool" check-config "$REPO/deploy/alertmanager.yml"
# 宛先を差し替えた写しも、スキーマとして正しいこと。
"$BIN/amtool" check-config "$WORK/alertmanager.yml"

cat > "$WORK/sink.py" <<'PY'
import http.server, json, os, sys
out = sys.argv[1]
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get('Content-Length', 0))
        body = json.loads(self.rfile.read(n) or b'{}')
        with open(out, 'a') as f:
            f.write(json.dumps(body) + '\n')
        self.send_response(200); self.end_headers()
    def log_message(self, *a): pass
http.server.HTTPServer(('127.0.0.1', 9099), H).serve_forever()
PY
rm -f "$WORK/received.json"
python3 "$WORK/sink.py" "$WORK/received.json" & SINK_PID=$!

rm -rf "$WORK/data"
"$BIN/alertmanager" --config.file="$WORK/alertmanager.yml" \
  --storage.path="$WORK/data" --web.listen-address=127.0.0.1:9093 \
  --cluster.listen-address= > "$WORK/am.log" 2>&1 & AM_PID=$!

for _ in $(seq 1 30); do
  # **自分が起動したものか確かめます。** 前の呼び出しの Alertmanager が
  # まだ 9093 を掴んでいると、ready には答えるが直後に終わります。
  kill -0 "$AM_PID" 2>/dev/null || break
  curl -sf http://127.0.0.1:9093/-/ready >/dev/null 2>&1 && break
  sleep 1
done
if ! kill -0 "$AM_PID" 2>/dev/null; then
  say "!! Alertmanager が起動直後に終了しました。**設定の問題ではありません**"
  cat "$WORK/am.log" >&2
  exit 2
fi
if ! curl -sf http://127.0.0.1:9093/-/ready >/dev/null 2>&1; then
  say "!! 起動しません"
  cat "$WORK/am.log" >&2
  exit 1
fi

say "== 2. 発火したアラートが receiver まで届くか"
post_alerts '[{"labels":{"alertname":"EDRHashIOCHasNothingToMatch","severity":"warning","team":"detection"},"annotations":{"summary":"delivery probe","runbook_url":"https://example.test/runbook#probe"}}]'
# 写しの group_wait は 1s。届くまで待ちます。
#
# **15 で足ります。** 30 にすると、group_wait の差し替えを外しても
# ぎりぎり届いてしまい、外したことに気づけません。
for _ in $(seq 1 15); do
  [ -s "$WORK/received.json" ] && break
  sleep 1
done

say "== 3. inhibit_rules が実際に抑制するか"
post_alerts '[{"labels":{"alertname":"EDRApiDown","severity":"critical","environment":"prod"},"annotations":{"summary":"src"}},{"labels":{"alertname":"EDRHighAPIErrorRate","severity":"warning","environment":"prod"},"annotations":{"summary":"tgt"}}]'
sleep 8

python3 - "$WORK/received.json" <<'PY'
import json, subprocess, sys
problems = []

try:
    got = [json.loads(l) for l in open(sys.argv[1])]
except FileNotFoundError:
    got = []
if not got:
    problems.append("通知が1件も届きませんでした。"
                    "**ルールを書くことと、誰かに届くことは別です**")
else:
    names = {a['labels'].get('alertname')
             for b in got for a in b.get('alerts', [])}
    if 'EDRHashIOCHasNothingToMatch' not in names:
        problems.append("投げたアラートが届いていません: %s" % names)
    rb = [a.get('annotations', {}).get('runbook_url')
          for b in got for a in b.get('alerts', [])]
    if not any(rb):
        problems.append("runbook_url が通知に載っていません。"
                        "**障害の最中に開くリンクなので、落ちると意味がありません**")

out = subprocess.run(
    ['curl', '-sS', 'http://127.0.0.1:9093/api/v2/alerts?inhibited=true'],
    capture_output=True, text=True).stdout
states = {a['labels'].get('alertname'): a.get('status', {}).get('state')
          for a in json.loads(out or '[]')}
if states.get('EDRHighAPIErrorRate') != 'suppressed':
    problems.append("inhibit_rules が抑制していません: %s。"
                    "**API が落ちているあいだ、その二次アラートも全部鳴ります**"
                    % states)
if states.get('EDRApiDown') != 'active':
    problems.append("抑制する側まで黙っています: %s" % states)

if problems:
    print("見つかった問題:")
    for p in problems:
        print("  - " + p)
    raise SystemExit(1)
print("ok — 設定は読める / 通知は届く（%d 通）/ inhibit は効く" % len(got))
PY
