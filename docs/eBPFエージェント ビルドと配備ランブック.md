# eBPF エージェント ビルドと配備ランブック（Linux）

Linux エージェントを **eBPF センサー有効**でビルド・配備する手順。既定ビルドとの違いは飾りではなく、
**これを踏まないと検知器が黙って無効化される**（後述の §5 参照）。

対象読者: 検証環境や本番 Linux エンドポイントに eBPF 版エージェントを入れる運用者・開発者。

---

## 0. なぜ eBPF ビルドが要るのか

| センサー | 既定ビルド | `-tags ebpf` ビルド |
|---|---|---|
| ファイル監視 | inotify | **eBPF**（openat tracepoint + vfs_unlink/vfs_rename kprobe）|
| ネットワーク監視 | `/proc/net` ポーリング | **eBPF**（tcp_connect kprobe）|

差は「精度が上がる」ではなく **検知できるかどうか**:

- **inotify は操作元 pid を報告できない**。ファイルイベントの `process_name` が常に空になり、
  プロセス単位で数える**ランサムウェア検知(T1486)が恒常的に無反応**になる。
- **`/proc/net` ポーリングは ESTABLISHED しか観測できない**。閉じたポートへの接続、つまり
  **ポートスキャンの本体(T1046)が丸ごと不可視**になる。

いずれも「アラートが出ない」だけで、エラーもログも出ない。**実機測定でしか露見しない**（実例＝
[results/live-20260726-detection-rate-scorecard.md](results/live-20260726-detection-rate-scorecard.md)）。

---

## 1. 前提条件

| 要件 | 確認コマンド | 備考 |
|---|---|---|
| カーネル BTF | `ls /sys/kernel/btf/vmlinux` | CO-RE に必須。Ubuntu 20.04+/RHEL 8.2+ は既定で有効 |
| clang ≥ 12 | `clang --version` | eBPF バイトコード生成 |
| bpftool | `bpftool version` | `vmlinux.h` 生成に使用 |
| libbpf ヘッダ | `ls /usr/include/bpf/bpf_core_read.h` | `libbpf-dev` |
| Go | `go version` | agent は独立モジュール（`agent/go.mod`）|
| root 権限 | — | eBPF プログラムのロードに必要 |

```bash
sudo apt-get update
sudo apt-get install -y clang llvm libbpf-dev linux-tools-common linux-tools-$(uname -r) make
```

> **BTF が無いカーネル**では CO-RE が使えないため、この手順は成立しない。エージェントは
> 自動的に inotify / `/proc/net` にフォールバックして動作は継続するが、上記の検知は無効になる。

---

## 2. ビルド

```bash
cd <repo>/agent

# (1) このカーネルの BTF から vmlinux.h を生成（CO-RE の型定義元。数万行になる）
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpf/vmlinux.h
wc -l ebpf/vmlinux.h        # 10万行前後なら成功

# (2) bpf2go で Go バインディングを生成
go generate ./internal/platform/linux/...

# (3) eBPF タグ付きでビルド
CGO_ENABLED=0 go build -tags ebpf -o /tmp/edr-agent-ebpf ./cmd/agent
```

`vmlinux.h` と bpf2go 生成物（`*_bpfel.go` / `*_bpfeb.go` / `*.o`）は **リポジトリに含まれない**
（カーネル依存のため）。ビルドホストごとに生成する。

---

## 3. 配備（systemd）

```bash
# ★ 順序が重要: 停止 → 配置 → 起動
sudo systemctl stop edr-agent-ebpf 2>/dev/null

sudo cp /tmp/edr-agent-ebpf /usr/local/bin/edr-agent-ebpf
sudo mkdir -p /var/log/edr-agent /var/lib/edr-agent /var/quarantine

sudo cp <repo>/agent/deploy/linux/edr-agent-ebpf.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now edr-agent-ebpf
```

> **`Text file busy`** が出たら、稼働中のバイナリを上書きしようとしている。必ず `stop` してから `cp`。

### unit が既定の unit と違う理由

`edr-agent-ebpf.service` は `deploy/scripts/install-agent.sh` が生成する既定 unit と意図的に異なる:

| 設定 | 理由 |
|---|---|
| `User=root` | eBPF プログラムのロード・kprobe/tracepoint アタッチに必要 |
| `LimitMEMLOCK=infinity` | BPF マップ確保がロックメモリ上限に課金される |
| `AmbientCapabilities=CAP_BPF CAP_PERFMON …` | 非 root 運用へ切り替える場合の要件を明示 |
| `ProtectKernelTunables` / `SystemCallFilter` **なし** | これらは `bpf(2)` / `perf_event_open(2)` を塞ぐ。**付けるとフォールバックする** |

---

## 4. 動作確認

```bash
# (1) eBPF ファイル監視が起動したか（フォールバックしていないか）
sudo journalctl -u edr-agent-ebpf -n 30 --no-pager | grep -iE "eBPF ファイル監視|フォールバック"
# 期待: "[file_monitor] eBPF ファイル監視を起動しました（pid/プロセス名を付与）"

# (2) ファイルイベントに pid/プロセス名が載っているか（サーバ側で確認）
docker exec kizashi-postgres psql -U edr -d edrplatform -c \
  "SELECT raw_data->>'operation' op, raw_data->>'process_name' proc, raw_data->>'pid' pid, count(*)
   FROM events WHERE agent_id='<AGENT_UUID>' AND event_type='file'
   AND time > now() - interval '2 minutes' GROUP BY 1,2,3 ORDER BY 4 DESC LIMIT 10;"
# 期待: proc が埋まり pid が非ゼロ。proc 空 / pid=0 なら inotify にフォールバックしている
```

### ランサムウェア検知の実機確認

```bash
# 使い捨てファイルを 60 個以上、既存ファイルとして上書き（O_CREAT なしで開く）
mkdir -p /home/<user>/ransomsim/{a,b,c,d,e}
for i in $(seq 1 70); do d=$(printf "abcde" | cut -c$((i%5+1))); echo seed > /home/<user>/ransomsim/$d/f$i.dat; done
python3 -c "
import os, glob
for p in sorted(glob.glob('/home/<user>/ransomsim/*/*.dat')):
    with open(p,'r+b') as f: f.write(os.urandom(1024))
"
# 期待（数秒後）: [HEURISTIC] ランサムウェアの疑い: プロセス 'python3' が30秒内に60個のファイルを破壊的操作
```

> `dd of=...` は `O_CREAT` 付きで開くため **CREATE 判定**になり、破壊的操作として数えられない。
> 既存ファイルを `r+b` で開いて上書きすること。

### ポートスキャン検知の実機確認

```bash
python3 -c "
import socket,subprocess
ip=subprocess.run(['hostname','-I'],capture_output=True,text=True).stdout.split()[0]
[socket.socket().connect_ex((ip,p)) for p in range(8000,8021)]
"
# 期待: [HEURISTIC] ポートスキャン検知: python3 が60秒内に15個の異なる宛先ポートへ接続
```

> ループバック(127.0.0.1)宛は network イベントとして報告されないため、**自ホストの LAN IP** を使う。
> `bash /dev/tcp` は**リバースシェルのシグネチャ**なので測定には使わない（別技術の検知が付いてしまう）。

---

## 5. 既知の落とし穴（すべて実機で踏んだもの）

| 症状 | 原因 | 対処 |
|---|---|---|
| ファイルイベントの `process_name` が空・`pid=0` | inotify にフォールバックしている | `-tags ebpf` でビルドしたか、unit の hardening が `bpf(2)` を塞いでいないか確認 |
| ポートスキャンが検知されない | eBPF ネットワーク監視が無効（`/proc/net` ポーリングは ESTABLISHED のみ観測） | 同上。過去には `prevention` タグ必須という誤ったゲートがあった（現在は `ebpf` のみで有効） |
| DB にイベントは入るのに検知が発火しない | エージェントがイベントに ID/Timestamp を設定していない → ingestion の msgID が衝突し **JetStream 重複排除**でバーストが1件に潰れる | コレクタで `ID`(uuid)/`Timestamp` を必ず設定する。DB は `event_id` 既定値で埋まるため**損失が見えない**のが厄介 |
| 監視対象外のはずのパスからイベントが大量に来る | eBPF はホスト上の**全**書き込み open が届く。監視パス未設定時に全許可すると `/var/lib/docker` 等まで拾う | `defaultMonitoredRoots`（inotify と共有）にフォールバックする実装になっているか確認 |
| 再起動でエージェントが消える | 手動起動している | systemd unit を `enable` する（§3）|
| `Text file busy` | 稼働中バイナリの上書き | `systemctl stop` してから `cp` |

---

## 6. 関連ドキュメント

- [ATT&CK検知率測定計画.md](ATT&CK検知率測定計画.md) — 測定手順と、測定時の必須設定（§9 注意・制約）
- [results/live-20260726-detection-rate-scorecard.md](results/live-20260726-detection-rate-scorecard.md) — 本ランブックの根拠となった実機検証記録
- [Linuxカーネル防御検証ランブック.md](Linuxカーネル防御検証ランブック.md) — prevention(LSM) 側の検証
- [エージェントインストール手順.md](エージェントインストール手順.md) — 既定（非 eBPF）ビルドの配布手順
