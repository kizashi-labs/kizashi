# Linux eBPF 短命プロセス検知の修正と実機検証

**実施日**: 2026-06-21〜22 / **環境**: RHEL 10.1 / kernel 6.12.0 / EC2（agent_id `9ed28fec…`、server `203-0-113-10.nip.io`）
**ブランチ**: `feat/active-defense-detection-deepening`（commit `9062722b`）/ **状態**: 実機で修正・検証済み（main マージ＋全配信は未）

---

## 0. 要約（TL;DR）

ATT&CK 検知率の自己測定を Linux 実機で回したところ、**textbook 級の悪性コマンド（base64 ステージャ／reverse shell／
SUID 付与 等）が検知 0** という結果になった。多層診断の末、原因は検知ルールの不足ではなく **eBPF プロセステレメトリの
3 つのバグ**（特に**タイムスタンプが 1970 年**になりイベントが時間窓から不可視）だと判明。3 つとも修正し、

> **検知率 0/6 → Technique レベル 4/5（+reverse shell 別途確認＝実効 5/6, 80%）** へ回復。検知→自動対応（AUTO_ISOLATE）
> までの全パイプライン動作を実機で実証した。

「検知エンジン・ルール・自動対応は元から商用 EDR 同等に機能していたが、**エージェントの可視性バグ 1 つが Linux 検知を
丸ごと無効化していた**」という構図だった。

---

## 1. 症状

- Linux agent（eBPF 出荷ビルド `-tags ebpf`）に対し、安全な検知-positive テクニック（base64 デコード実行・curl→/tmp・
  SUID 付与・/tmp 実行・/etc/shadow 読取・reverse shell）を流しても、**サーバの events / alerts に短命プロセスが現れず検知 0**。
- 長命プロセス（sleep, curl, bash 等）の create イベントは見えるのに、**サブ秒で終わるプロセスだけが消える**ように見えた。

## 2. 診断の経緯（誤診も含む）

| 仮説 | 検証 | 結論 |
|---|---|---|
| /proc レース（短命は /proc 読取前に exit） | コードと trace で確認 | **誤り**。comm/filename はカーネル内取得済み |
| reader がレコードを drop | reader に計器ログ | size チェックのバグを発見（下記②） |
| eBPF が短命 exec を取りこぼす | `bpf_printk` を `handle_exec` に挿入 → trace_pipe | **誤り**。`vigEXEC … comm=whoami` が発火、pid==tid、comm 正常 |
| サーバが drop/空保存 | ingestion コード確認 | raw_data 構築は素直、drop 無し |
| **イベントが 1970 年保存で時間窓から不可視** | `from=1970-01-01` 窓で query | **正解**。`create pn=[whoami] cmd=[whoami]` が 1970 年で完全保存されていた |

教訓: **「サーバに無い」＝「保存されていない」ではない。**時間窓クエリの前提（タイムスタンプの正しさ）を疑うこと。

## 3. 根本原因（3 層のバグ）

### ① argv をカーネル内で取得していなかった
`handle_exec`（sched_process_exec tracepoint）は comm/filename は取っていたが **argv（コマンドライン）は未取得**で、
ローダが `/proc/<pid>/cmdline` で後追いしていた（短命では間に合わない）。
→ **`mm->arg_start..arg_end` から `bpf_probe_read_user` でカーネル内取得**。verifier 対策として長さを
`MAX_ARGS_LEN-1` でクランプ＋`&(MAX_ARGS_LEN-1)` マスク（`MAX_ARGS_LEN` は 2 のべき乗）。これで過去 #191 の
`R2 min value is negative` 拒否を回避し、kernel 6.12 の verifier に受理された。

### ② reader のサイズチェック誤り（全レコード破棄）
`ebpf_loader.go` の `if len(record.RawSample) < int(unsafe.Sizeof(ebpfProcessEventFull{}))` が **全レコードを drop** していた。
`args_len`（u32）追加で **Go 構造体は 824B に丸まる一方、BPF ringbuf レコードは詰めた 820B**。`unsafe.Sizeof(824) > 820`
となり常に弾かれた。→ 閾値を **`binary.Size`（パック実サイズ＝820）** に変更。

> 教訓: **BPF ringbuf レコード長の判定に `unsafe.Sizeof` を使うな。**`binary.Size`（Go アラインメント padding を含まない
> パック実サイズ）を使う。

### ③【真因】ktime タイムスタンプで全 eBPF イベントが 1970 年保存
`process_monitor.bpf.c`: `event->timestamp_ns = bpf_ktime_get_ns()` は **起動からの経過ナノ秒（boot 相対・単調増加）**。
これを `ebpf_loader.go` が `time.Unix(0, int64(raw.TimestampNs))` で **epoch 相対**として変換していたため、全 eBPF
プロセスイベントの時刻が **1970-01-01 + 稼働時間** になっていた。
→ events テーブルの `time` 列が 1970 年 → **2026 年の時間窓クエリと、検知エンジンの時間窓相関の双方から不可視**。
short/long を問わず全 eBPF イベントに影響していた（＝「Linux 検知 0」の正体）。
→ **reader 受信時刻 `time.Now()` に修正**（eBPF イベントは exec から ms 以内に処理されるので実用上十分な精度）。

## 4. 修正内容（コード）

| ファイル | 変更 |
|---|---|
| `agent/ebpf/process_monitor.bpf.c` | 構造体に `__u32 args_len` 追加。`handle_exec` で argv をカーネル内取得（clamp+mask） |
| `agent/internal/platform/linux/ebpf_loader.go` | `ArgsLen` ミラー、`argvToCmdline()`、サイズ閾値を `binary.Size` へ、**`Timestamp: time.Now()`** |
| `agent/internal/platform/linux/ebpf_loader_test.go` | `argvToCmdline` の純ロジックテスト（新規） |

> 診断用に一時挿入した `bpf_printk`（vigEXEC/EXIT/SUBMIT/RESERVEFAIL）と reader の計器ログは、原因特定後に**除去済み**。

## 5. 実機ビルド & 差し替え手順（RHEL EC2・再現可能）

> **前提（箱に揃っている）**: `go 1.26.3` / `git` / `clang` / `bpftool` / `libbpf-devel` / BTF(`/sys/kernel/btf/vmlinux`) / sudo。
> server コンテナはこの箱ではなく別ホスト稼働（この箱は agent 検証専用）。

```bash
# 1) ソース取得(zipball が最も確実。base64 ペーストは大きいと破損する)
export PAT='<GitHub PAT (repo読み取り)>'
REPO=kizashi-labs/kizashi; BR=feat/active-defense-detection-deepening
rm -rf ~/edrbuild && mkdir -p ~/edrbuild
curl -sL -H "Authorization: token $PAT" "https://api.github.com/repos/$REPO/zipball/$BR" -o /tmp/src.zip
file /tmp/src.zip | grep -q Zip || { echo "DL失敗(PAT確認)"; head -c150 /tmp/src.zip; }
unzip -q /tmp/src.zip -d ~/edrbuild; SRC=$(ls -d ~/edrbuild/*/ | head -1)

# 2) go.mod を箱の go(1.26.3)へ整合(リポジトリは 1.26.4 指定・箱は GOTOOLCHAIN=local)
sed -i -E 's/^go 1\.26\.[0-9]+.*/go 1.26.3/; /^toolchain /d' "$SRC/agent/go.mod"

# 3) bpf2go 再生成(C を変えた時のみ) → ビルド
cd "$SRC/agent"
bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpf/vmlinux.h
( cd internal/platform/linux && GOPACKAGE=linux go run github.com/cilium/ebpf/cmd/bpf2go \
    -tags ebpf -cc clang -cflags "-O2 -g -target bpf -D__TARGET_ARCH_x86" \
    ProcessMonitor ../../../ebpf/process_monitor.bpf.c )
go build -tags ebpf -o /tmp/edr-agent-fix ./cmd/agent

# 4) 差し替え(systemd サービスは止め、手動フォアグラウンドで起動。設定は再利用)
sudo systemctl stop edr-agent; sudo pkill -f edr-agent; sleep 2
sudo cp /tmp/edr-agent-fix /opt/edr-agent/edr-agent-fix; sudo chmod +x /opt/edr-agent/edr-agent-fix
sudo restorecon /opt/edr-agent/edr-agent-fix 2>/dev/null || true
sudo bash -c 'nohup /opt/edr-agent/edr-agent-fix --config /etc/edr-agent/config.toml >/tmp/fix.log 2>&1 &'
sudo bpftool prog show | grep -E 'handle_exec|handle_exit'   # tracepoint ロード＝verifier 受理の確認
```

**復旧（baseline へ戻す）**: `sudo pkill -f edr-agent-fix; sudo systemctl start edr-agent`
（systemd の `edr-agent.service` は旧ポーリング版を起動。再起動時も自動で baseline に戻る）。

## 6. 検証結果（before / after）

同一の検知-positive バッテリーで比較（reverse shell は sev9＝自滅回避のため本表からは除外、別途確認）:

| Technique | 修正前 | 修正後 |
|---|---|---|
| T1140 base64 難読化実行 | None | **Technique**（SIGMA Base64 Obfuscation） |
| T1105 curl→/tmp | None | **Technique**（curl/wget Download to Temp） |
| T1166 SUID 付与 | None | **Technique**（SUID Bit Set） |
| T1059 /tmp 実行 | None | **Technique**（/tmp・/dev/shm 実行） |
| T1087.001 /etc/shadow 読取 | None | Telemetry（file_access 系＝FIM 連動が要） |
| **検知率** | **0/6** | **検知 4/5・解析検知(Technique) 4/5 = 80%** |

- **timestamp 修正の確認**: 修正後、短命プロセスが 2026 年窓に `create pn=[whoami] cmd=[whoami]` として出現。
- **検知→自動対応の実証**: reverse shell（T1059.004, sev9）が検知され **AUTO_ISOLATE が自動隔離を発火**（その結果 SSH が
  遮断された＝後述）。検知だけでなく対応まで動くことを実機で確認。

## 7. 運用上の注意（ハマりどころ）

- **⚠️ 検知が動くと自分が隔離される**: sev≥9（既定 `AUTO_ISOLATE_MIN_SEVERITY`）のアラートで AUTO_ISOLATE が発火し、
  被験 VM が「サーバ IP のみ許可」に隔離され **SSH が切れる**（実際に発生）。検知バッテリー実行時は
  ① `AUTO_ISOLATE_MIN_SEVERITY` を一時的に上げる/audit化、または ② sev9 未満に限定（reverse shell 等を除外）。
  - **復旧**: 別ホストから `POST /api/v1/agents/{id}/unisolate`（admin 認証。agent がサーバ接続を保てば隔離解除コマンドが届く）。
    最終手段は EC2 再起動（iptables は揮発性なので隔離ルールは消える）。
- **バイナリ整合性チェック**: 差し替え時に「エージェントバイナリの改ざんを検知」ERROR がログに出るが、agent は停止せず
  継続する（tamper 機能が想定通り検知したもの）。
- **大きなファイルの転送**: SSH 越しの巨大 base64 ペーストは破損する（heredoc に後続コマンドが割り込む等）。**zipball 取得が確実**。
- **go.mod のバージョン**: 箱の go が `GOTOOLCHAIN=local` のため、リポジトリの `go 1.26.4` 指定だとビルド不可。
  `go 1.26.3` へ下げる（上記手順 2）。

## 8. 残課題

1. **main へマージ → CI/`docker.yml` で全エンドポイントへ配信**（現状 feature branch のみ・検証 EC2 は手動 swap）。
2. **Windows ETW 側の本測定**（Tier1+2、Atomic フル）。Win box は時計ズレ要修正。
3. **AUTO_ISOLATE 無効化下での完全バッテリー**（sev9 含む reverse shell も採点に入れる）と MTTD/FP/防御率の取得。
4. `/etc/shadow` 等 **file_access 系の検知**は FIM 連動が要（現状 Telemetry 止まり）。
5. 偵察バースト検出器の `value_any` に **Linux 固有プロセス名**（`ps`/`uname`/`id`/`ss`/`cat /etc/passwd` 等）を追加。

---

## 9. 追補：コミット済 `.o` が stale で process イベントが全消失していた（2026-06-30, Ubuntu kernel 6.8）

§8-1 の「main マージ／全配信」へ進む過程で、**出荷経路の `.o` が古く、eBPF をロードしても `process`
イベントが 1 件もサーバへ届かない**残バグを特定・修正した。入口は Caldera 採点
（[ops/Caldera多段エミュレーション採点.md](ops/Caldera多段エミュレーション採点.md)）で Linux 収集チェーンの検知が
0/11（全 Telemetry 止まり）だったこと。

### 真因
- `bpftool btf dump file processmonitor_bpfel.o format c` で `.o` の `struct process_event` を見ると
  **`args_len` フィールドが無い（816 バイト）**。一方 Go デコーダ `ebpfProcessEventFull` は末尾に
  `ArgsLen uint32` を持ち **820 バイト（= `binary.Size` = needBytes）**。
- カーネルが書く 816B レコードが needBytes(820) 未満になり、`ebpf_loader.go` の
  `if len(record.RawSample) < needBytes { continue }` で **全 ringbuf レコードが無言で破棄**されていた。
- §7 の「ktime」「サイズチェック」修正は Go 側に入っていたが、**コミット済 `.o` 自体が `args_len` 追加前の
  古い世代**だった（main と feature ブランチに同じ古い `.o` が載っていたため「blob 一致＝最新」と誤認しやすい）。
  **kernel 6.8/6.12 差は無関係**。

### 修正（in-place 再生成。clang さえあれば RHEL/CI に依らない）
```
sudo apt-get install -y clang llvm libbpf-dev          # Ubuntu。RHEL は dnf + CRB の libbpf-devel
cd /home/ubuntu/edr-platform/agent
bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpf/vmlinux.h
( cd internal/platform/linux && GOPACKAGE=linux go run github.com/cilium/ebpf/cmd/bpf2go \
    -cc clang -cflags "-O2 -g -target bpf -D__TARGET_ARCH_x86 -I/usr/include" \
    ProcessMonitor ../../../ebpf/process_monitor.bpf.c )      # ← .o 再生成（args_len 入り 820B）
go build -tags ebpf -o /tmp/edr-agent-ebpf ./cmd/agent
```
再生成した `processmonitor_bpf*.{go,o}` をコミット（§8-1 の積年「残: bpf2go 生成物未コミット」も解消）。

### 検証（実機 Ubuntu kernel 6.8）
- 配備後 `process` イベントが **0 → 444 件/60s（command_line 付き）**流入を確認。
- Caldera Thief フルチェーン（22 リンク）で Linux collection/exfil ルール（migration 285）と合わせ
  **検知率 0%→100%（MISS 0・Technique 72.7%・MTTD 1s）**を実証。

### 教訓
- **`.o` の鮮度は BTF ダンプで確認する**（`bpftool btf dump file <obj> format c` の struct サイズが Go デコーダと
  一致するか）。ファイルの blob 一致は「最新」を意味しない。
- プロセス停止に `pkill -f "<path>"` を使うと、リモートシェルの argv に同パスが含まれて**自滅 kill**する。
  `pgrep -x <comm>` か PID 指定を使う。

---

## 10. 追補：drop の定量実測と非 eBPF ビルドの残存 drop（2026-07-07, Ubuntu kernel 6.8）

§7・§9 の修正が効いているかを、稼働中の eBPF エージェント（kernel 6.8、`bpftool prog show` で `handle_exec` /
`handle_execveat` / `handle_exit` tracepoint ロード済み）に対して**制御負荷で定量**した。

| テスト | 期待 | 結果 |
|---|---|---|
| 短命（瞬時終了 `/bin/true` コピー）40 プロセス（ユニーク名） | 全捕捉 | **40/40（0 drop）** |
| バースト 700 プロセス（500 連続 + 200 並列の `/bin/true`） | 全捕捉 | **700/700（0 drop）** |

→ **eBPF ビルドはテレメトリを一切取りこぼさない**（exec 時にカーネル内で捕捉するため、ポーリング粒度も
userspace エンリッチのレースも無い）。§9 の `.o` 鮮度修正後の状態が健全であることを実機で確認。

### 非 eBPF（出荷デフォルト）ビルドの drop 源
`process_ebpf.go` の `NewEBPFProcessCollector` はタグ無しビルドでは stub が必ず失敗し **`pollProcFS`（/proc を 200ms
間隔で差分ポーリング）へフォールバック**する。2 つの drop 源のうち:

1. **構造的 drop（残存）**: 200ms 未満で起動→終了する短命プロセスは PID がスナップショットに現れず**恒久的に不可視**。
   （本追補の `/bin/true` テストは非 eBPF ビルドでは大半が消える。）→ 根治は「標準を eBPF ビルドに昇格」。
2. **バックプレッシャ drop（根治済）**: 送信チャネル満杯時の `select{case out<-evt: default:}` サイレント破棄は、
   **PR #426 が `sendProcEvent`（blocking + ctx 対応）に統一して根絶**（[技術的負債と改善計画.md](技術的負債と改善計画.md) P4-2）。

標準配布エージェント（`edr-agent-linux-amd64`, `server/Dockerfile` は `-tags ebpf` 無し）はポーリング動作なので、
実エンドポイントには構造的 drop が残る。詳細は [検知率向上_20260707_baseline実行元ゲートとLinuxシステム永続化FIM.md](検知率向上_20260707_baseline実行元ゲートとLinuxシステム永続化FIM.md) §2。

---

## 関連ドキュメント
- [ATT&CK検知率測定計画.md](ATT&CK検知率測定計画.md) — 測定の枠組みと第1回実測結果（§11）
- [ops/Caldera多段エミュレーション採点.md](ops/Caldera多段エミュレーション採点.md) — 多段採点の実施結果と運用知見（本件の入口）
- [技術的負債と改善計画.md](技術的負債と改善計画.md) — P4-2 に本件を記録
- [Linuxカーネル防御検証ランブック.md](Linuxカーネル防御検証ランブック.md) — eBPF LSM（能動防御）側の検証手順
