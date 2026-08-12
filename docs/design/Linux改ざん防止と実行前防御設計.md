# Linux 改ざん防止・常時オン収集・実行前防御 設計/実装計画書

**作成日**: 2026-06-19
**対象**: 商用化ロードマップ 優先課題①(改ざん防止＋常時オンのカーネル/eBPF収集)・②(実行前防御=prevention)
**スコープ**: Linux 優先（Windows/macOS は将来章で方針のみ）
**ステータス**: **完了。Ph0〜Ph6＋server 側 Ph1/Ph2 を全て実機実証（2026-06-19, RHEL10.1/kernel6.12/EC2）。Ph2 server 受信は2つの既存サイレント断線（#244 ingestion 破棄／#269 CHECK 制約）を発見・修正し、agent→ingestion→DB の完全ライブ実証でクローズ**

> 進捗サマリ（詳細は [技術的負債と改善計画.md](../技術的負債と改善計画.md) P4-4、検証手順は [Linuxカーネル防御検証ランブック.md](../Linuxカーネル防御検証ランブック.md)）。"実機実証" の粒度は厳密に:
> - **Ph0**(#225) execve 拒否 / **Ph3**(#228-230) enforce 拒否 exit126・既定 exit0 / **Ph4**(#231) kill 検知 / **Ph5**(#232) 拒否→disarm→許可 — いずれも実機実証。
> - **Ph1**(#226) 実機実証（agent: `mode=enforce`／server: heartbeat POST→`UpdateProtectionMode`→DB `protection_mode=enforce`、migration 268 適用済）。
> - **Ph2**(#227) **完全ライブ実証**（agent→ingestion→DB）。最終確認で2つの既存サイレント断線を修正：#244=ingestion が process_block を破棄／#269=events CHECK 制約が process_block を拒否(23514)。本番 agent を現 main に更新後、`events` に `event_type=process_block`＋payload 保存を実機確認。教訓=新 event_type は eventTypeString＋ingestion 昇格＋CHECK 制約の3点更新が必須。
> - **Ph6**(#236-238) 配布完了：`edr-agent-linux-amd64-ebpf` を CI 内生成（clang+bpftool ソースビルド+runner BTF、生成物コミット不要）でビルド→downloads/ 配信。`docker.yml` で server 反映＋migration 268 適用済。
> - 全コードは `prevention` build タグでゲート（既定ビルド非影響）。標準ポーリング版は従来配信、本変種は lsm=bpf ホスト向け opt-in。

---

## 0. なぜこの2つが最優先か

商用EDR(CrowdStrike / SentinelOne / Defender for Endpoint)との比較で、本製品の機能の「幅」は肉薄しているが、EDRの根幹で次の決定的差がある。

| 観点 | 現状 | 商用EDR | 本計画で埋める項目 |
|---|---|---|---|
| 防御モデル | 検知後に kill する**事後対応のみ** | 実行をインラインで**ブロック** | ② 実行前防御 |
| 収集の堅牢性 | eBPF は **opt-in**、失敗時ポーリング降格 | 常時オンのカーネルテレメトリ | ① 常時オン収集 |
| 改ざん耐性 | ユーザーランド agent、**管理者/マルウェアに停止可能** | カーネル保護 + tamper protection | ① 改ざん防止 |

「攻撃を可視化して事後対応する」ことはできても「その場で止める」「agent 自身を守る」ができない。これを Linux で先に解消する。

---

## 1. 現状アーキテクチャ（接地点）

実装済みコードに基づく事実：

- **収集(observe)**: `agent/ebpf/*.bpf.c` は **tracepoint ベースの観測専用**。
  - `process_monitor.bpf.c`: `tracepoint/sched/sched_process_exec` / `sched_process_exit` → ring buffer → ユーザーランドで `/proc` 補完。
  - ローダ: `agent/internal/platform/linux/ebpf_loader.go`（cilium/ebpf + `bpf2go` 生成、kernel ≥5.8、`//go:build linux && ebpf`）。
  - 観測のみで、カーネルに対し**戻り値で拒否する経路を持たない**。
- **レスポンス(respond)**: `agent/internal/response/manager.go` が gRPC コマンドを dispatch。
  - `isolate_network`(iptables/nftables) / `kill_process` / `quarantine_file`。
  - いずれも**検知→サーバ判断→コマンド配信→実行**の往復後に作動する事後対応。レイテンシは秒オーダー。
- **指令/ポリシー経路**: `agent/internal/transport/policy_sync.go` の gRPC コマンドストリーム + `policy.Manager` の定期同期。**本計画はこの既存経路を再利用する**（新トランスポートは作らない）。

→ 「実行前に止める」「agent を守る」には、**カーネル内で同期的に判定して拒否できる仕組み**が必要。Linux ではこれが **eBPF LSM (KRSI)**。

---

## 2. 設計の核：eBPF LSM (KRSI) を共通基盤にする

項目①の改ざん防止と②の実行前防御は、**同じ機構＝eBPF LSM フック**で実現できる。カーネルドライバ(.ko)を書かずに済み、署名・配布・BSOD相当(kernel panic)リスクを大幅に下げられるため Linux 優先の合理性が高い。

eBPF LSM プログラムは LSM フックに attach し、**戻り値 `-EPERM` 等でカーネル操作を同期的に拒否**できる（観測専用の tracepoint と決定的に違う点）。

### 必要なカーネル要件

| 要件 | 値 | 備考 |
|---|---|---|
| カーネル | **≥ 5.7**（BPF LSM 導入）。実運用は ≥5.13 推奨（`bpf_d_path` 等が安定） | 既存 observe は ≥5.8 |
| ビルド | `CONFIG_BPF_LSM=y` | 主要ディストロは概ね有効 |
| 起動 | `lsm=...,bpf`（または `CONFIG_LSM` に bpf 同梱） | **デフォルト未同梱のディストロが多く、要 GRUB 設定** |
| BTF | `/sys/kernel/btf/vmlinux` 存在（CO-RE） | RHEL 10.1 / Ubuntu 22.04+ で確認済（既存 eBPF と同条件） |

> **重要な現実制約**: `lsm=bpf` はブートパラメータ変更＝**再起動が必要**な環境が多い。これは「常時オン」の理想と相反するため、§6 のフォールバック戦略（LSM 不可なら観測+事後 kill に縮退）を必須とする。

### フック対象（候補）

| 目的 | LSM フック | 拒否時の効果 |
|---|---|---|
| ② 実行前ブロック | `bprm_check_security` | `execve` を実行前に拒否（最重要） |
| ② ファイル実行/読取制御 | `file_open` / `mmap_file` | 悪性バイナリの open/mmap を拒否 |
| ② ネットワーク発信ブロック | `socket_connect` | C2 への接続を発生前に遮断 |
| ① agent プロセス保護 | `task_kill` | 非認可プロセスから agent への kill/SIGSTOP を拒否 |
| ① agent バイナリ/設定保護 | `file_open`(write)/`inode_unlink`/`inode_rename` | agent 実行ファイル・設定・eBPF pin の改竄/削除を拒否 |
| ① ptrace 防御 | `ptrace_access_check` | agent への ptrace アタッチ(メモリ改竄/デバッグ)を拒否 |
| ① eBPF アンロード防御 | `bpf`(BPF_LINK_DETACH 等) | 自身の保護プログラムの剥がしを拒否 |

---

## 3. 項目①：常時オン収集 + 改ざん防止

### 3-1. 常時オン化

現状の opt-in(`ebpf` build tag + 実行時フラグ)を、**既定で起動を試行し、可否を heartbeat で申告**する方式へ。

- 起動時に「BPF LSM 利用可否」「BTF 有無」「kernel version」を検査し、3段階の**収集モード**を決定:
  1. `enforce`（LSM 利用可）= 観測 + 実行前防御 + 改ざん防止
  2. `observe`（eBPF 可・LSM 不可）= 現状の観測 + 事後 kill
  3. `poll`（eBPF 不可）= `/proc` ポーリング（最終フォールバック）
- 決定したモードを **heartbeat / agent メタデータでサーバへ申告** → 管理画面で「このエンドポイントは prevention 有効か」を可視化（商用上の信頼性訴求にも直結）。

### 3-2. 改ざん防止(tamper protection)

eBPF LSM で agent 自身を保護する。**保護対象は「自分の PID・自分の実行ファイル・設定・pin された BPF オブジェクト」に限定**し、過剰防御で OS 管理を阻害しない。

設計上の要点:
- **認可主体の識別**: 「誰が agent を止めてよいか」を、単純な PID 一致でなく**署名済みの管理操作**（後述のローカル管理ソケット経由 + ワンタイムトークン）でのみ許可。`systemctl stop` 等の正規停止は、agent が事前に「自己保護一時解除」フラグを LSM マップに立ててから行う。
- **二要素的な解除**: サーバからの正規アンインストール指令（gRPC コマンドに新設 `disarm_tamper_protection`）を受けて初めて保護マップをクリア → その後に停止/削除を許可。これで「ローカル管理者を乗っ取ったマルウェア」からは守りつつ、正規運用の停止/更新は通す。
- **フェイルセーフ**: agent プロセスが異常終了した場合に保護フックが残って OS を操作不能にしないよう、保護 BPF プログラムは **agent が握る fd / BPF link のライフタイムに紐付け**、agent 消滅時に自動デタッチされる設計にする（pin はしない、もしくは watchdog 管理）。

> tamper protection は「強すぎると自分の足を撃つ」典型。**段階導入（まず警告ログ→次に kill 拒否→最後に削除拒否）**とし、各段で誤爆を計測する。

---

## 4. 項目②：実行前防御 (prevention)

### 4-1. 判定モデル

カーネル内 LSM フックは**高速・同期**でなければならない（プロセス生成のたびに走る）。複雑な検知（Sigma/YARA/ML）はユーザーランド/サーバ側で行い、**カーネルには「単純な照合テーブル」だけを置く**。

```
[サーバ: 検知エンジン/IOC/YARA/Sigma]
        │  prevention ポリシー(ブロックリスト)を配信
        ▼
[agent ユーザーランド: policy.Manager]
        │  BPF マップへ書き込み(ハッシュ/パス/inode/接続先)
        ▼
[カーネル: eBPF LSM フック]  ← execve/open/connect のたびにマップ照合 → -EPERM
```

- カーネルに置くのは「ブロック対象の SHA256（先頭バイト or inode キー）」「禁止パス prefix」「禁止接続先(IP/port)」等の**O(1)照合可能なデータのみ**。
- ハッシュ照合は execve 時点ではコスト高。**第一段は「inode + dev + mtime」「実行パス」「親子チェーン」での即時ブロック**を主とし、ハッシュ確定ブロックはユーザーランドで `file_open` を保留→ハッシュ計算→判定する非同期方式を §4-3 で別途検討。

### 4-2. ポリシー配信（既存経路の再利用）

新トランスポートは作らない。`policy_sync.go` の gRPC ポリシー同期に **prevention ポリシー型**を追加:

- 新コマンド型（`response/manager.go` に追加）: `apply_prevention_policy` / `clear_prevention_policy`。
- `policy.Manager` が prevention ルール集合を保持し、差分を BPF マップへ反映。
- サーバ側: 既存の IOC / 検知ルールに「`action: block`」属性を追加し、prevention 対象を派生生成（検知ルールの再利用で運用負荷を上げない）。

### 4-3. fail-open / fail-close ポリシー（最重要の設計判断）

| モード | 挙動 | 用途 |
|---|---|---|
| **fail-open（既定）** | 判定不能・agent 異常時は**通す** | 可用性優先。誤ブロックで業務停止を避ける。商用初期の既定 |
| **fail-close（opt-in）** | 判定不能時は**拒否** | 高セキュリティ要件のテナント向け。要明示設定 |

- prevention は**テナント/ポリシー単位で enforce/audit を切替**。`audit` モードでは「ブロックしたはずのイベント」をアラート化するだけで実際には通す → **本番投入前に誤検知を必ず audit で計測**してから enforce へ昇格（自動隔離の段階導入と同じ思想）。

### 4-4. パフォーマンス制約

- LSM フックはホットパス。**マップ照合は数命令で完結**させ、文字列比較やループは避ける。
- execve あたりの追加レイテンシ目標: **< 50µs（p99）**。ベンチ（`hyperfine` でビルド/起動の回帰）を CI 外で計測。
- ring buffer 溢れ・マップ満杯時の挙動を定義（溢れ時は fail-open + カウンタ計上 + アラート）。

---

## 4.5. 項目③：認証情報/メモリアクセス検知（credaccess, T1003/T1055）＜2026-07-02 実装・実機実証, [PR#372](https://github.com/kizashi-labs/kizashi/pull/372)＞

§2 の同一 LSM 基盤の**第3の用途**。フック `ptrace_access_check` を①(agent 自己防御=拒否)
ではなく**検知(audit-only)**に転用し、あるプロセスが他プロセスのメモリを読む操作
（`gdb -p`, `/proc/<pid>/mem`, `process_vm_readv`, ptrace）= **Linux 版 LSASS アクセス相当**を
捕捉して `credential_access` テレメトリ（T1003 認証情報ダンプ / T1055 プロセスインジェクション）
として送出する。Windows は別経路（LSASS アクセスドライバ）で同型イベントを既に生成しており、
本実装で **Linux emit 経路の欠落を解消**した。

- **BPF**（`agent/ebpf/credaccess_lsm.bpf.c`）: `SEC("lsm/ptrace_access_check")`。tamper_lsm と同型
  （ring buffer + 定数 return で verifier 適合）。tracer→target を申告し **常に `return 0`（拒否しない）**。
  自己アクセス・カーネルスレッドは除外。
- **ローダ/emit**（`credaccess_runner.go` / `cmd/agent/cred_linux.go`）: 自己 PID 除外 + 10s dedup、
  `BuildCredentialAccessEvent` で送出。`-tags "ebpf prevention"`、BPF LSM 非対応ホストでは no-op。
- **検知（server）**: `detection/engine.go` が `access_mask` の `ptrace_mode=` 有無で Linux/Windows を分岐。
  Linux は **良性システムトレーサを allowlist**（systemd*/runc/containerd/landscape 等、prefix 一致・
  comm 15 字切詰対応）で抑制し、非 allowlist のトレーサ（gdb/strace/python/dd 等）のみ T1003/T1055 化。
  機微ターゲット（sshd/keyring/agent 等）へのアクセスは severity 昇格。

> **⚠️ 重要な運用制約（§2 の `lsm=bpf` 要件を再確認）**: 本機能は §2 の tamper/prevention と
> **同じ `lsm=bpf` 要件**を持つ。BPF LSM プログラムは `bpf` が active LSM リストに無いと
> **attach は成功するが実行時に一度も呼ばれない**（`/sys/kernel/security/lsm` に bpf が無い＝
> `bpf_lsm=false`。起動ログの「起動しました」は attach 成功を意味するだけで発火保証ではない）。
> 検証EC2（Ubuntu 6.8, 203.0.113.10）は既定で bpf 不在だったため GRUB `lsm=…,bpf` 追記＋再起動で
> 有効化して実証した（run_cnt>0 で発火確認、strace attach → `credential_access` 保存を確認）。
> 詳細手順は[Linux カーネル防御 検証ランブック](../Linuxカーネル防御検証ランブック.md) §10。

> **配線の教訓**: `credential_access` は proto/ingestion/payload/Windows emit まで存在したが、
> ① Linux emit 経路の欠落 ② `events_event_type_check` 制約に `credential_access` が無く INSERT が
> SQLSTATE 23514 で拒否され**全プラットフォームでサイレント破棄**（migration294 で追加）
> ③ TargetImage が "lsass.exe" ハードコードで Linux 実ターゲットを誤報告、の 3 段が重なっていた。
> #269/#271（process_block/memory）と同型の「部品は在るが繋がっていない」故障。

---

## 4.6. 追加 eBPF センサ（tracepoint/kprobe, 2026-07-03）

§2 の同一 eBPF 基盤で、LSM（拒否）ではなく **tracepoint/kprobe（観測）**の report-only センサを2つ追加。
いずれも `-tags "ebpf prevention"` ゲート・非対応ホストは no-op。実機実証済。詳細:

> **🔴 2026-07-26 訂正: この `-tags "ebpf prevention"` 一括ゲートは誤りだった。**
> 本節の2センサは report-only（LSM アタッチも `-EPERM` 返却もブロック判定も持たない純テレメトリ）なので、
> **`prevention` 層に属する必要がない**。一方 `ci.yml` の標準 Linux 出荷ビルドは **`-tags ebpf` のみ**を渡すため、
> 両センサは**出荷される全ビルドでデッドコード**になっていた（consumer が常にビルド対象外）。
> 基盤（eBPF）を共有することは、配布ゲート（`prevention`）を共有する理由にならない。
>
> - **connect() テレメトリ**: [PR #544](https://github.com/kizashi-labs/kizashi/pull/544) で
>   `-tags ebpf` へ修正済み（`ci.yml` に NetworkMonitor の bpf2go 生成ステップも追加）。
> - **fileless/メモリ内実行**: 2026-08-01 に `-tags ebpf` へ修正済み（consumer 側3ファイルを一括是正し、
>   `ci.yml` / `release.yml` の生成ステップも整備）。T1620 / T1055 のディスクレス実行検知が
>   標準 Linux 出荷ビルドで発火するようになった。
>
> 詳細＝[検知率向上_20260726_prevention誤ゲートによるeBPF死角.md](../検知率向上_20260726_prevention誤ゲートによるeBPF死角.md)
[live-20260703-detection-depth.md](../results/live-20260703-detection-depth.md) /
[live-20260703-linux-behavioral-detectors.md](../results/live-20260703-linux-behavioral-detectors.md)。

- **fileless/メモリ内実行**([PR#390](https://github.com/kizashi-labs/kizashi/pull/390),
  `ebpf/fileless_monitor.bpf.c`): tracepoint `sys_enter_execveat`（`AT_EMPTY_PATH` = memfd/fd から
  ディスク無しで実行 = T1620 Reflective Code Loading / T1055）+ `sys_enter_memfd_create`。強シグナル
  (execveat AT_EMPTY_PATH) のみを既存 memory イベント経路(`BuildMemoryEvent`)で送出。回避テストで
  MISS だった fileless 実行を根治。
- **connect() テレメトリ**([PR#384](https://github.com/kizashi-labs/kizashi/pull/384),
  休眠中の `ebpf/network_monitor.bpf.c` を配線): kprobe `tcp_connect`(SYN 時点=失敗/閉ポートも捕捉)。
  `/proc/net/tcp` ポーリングが取りこぼす接続試行を出し、サーバ側ポートスキャン検知(T1046)を発火可能に
  する。★検知は「サーバ側ロジック × agent 側テレメトリ粒度の両輪」を示した例。

> **メモリ内 YARA 併用**([PR#393](https://github.com/kizashi-labs/kizashi/pull/393)):
> M1 メモリスキャナが見つける **RWX 領域のみ**を /proc/mem 読取 → curated な in-memory YARA で走査
> (Cobalt Strike 等)。★ファイル走査用の HKTL/PE ルールは生メモリで過一致するため流用禁止＝メモリ
> 専用ルールが必須(実機で vDSO/JIT の FP 氾濫を踏んで学習)。

---

## 5. ポリシー/コマンド経路まとめ（新設インターフェース）

| 種別 | 名称 | 方向 | 内容 |
|---|---|---|---|
| gRPC コマンド | `apply_prevention_policy` | server→agent | ブロックリスト差分を BPF マップへ |
| gRPC コマンド | `clear_prevention_policy` | server→agent | prevention 全クリア |
| gRPC コマンド | `disarm_tamper_protection` | server→agent | 正規アンインストール/更新前の保護解除 |
| heartbeat 拡張 | `protection_mode` | agent→server | `enforce`/`observe`/`poll` を申告 |
| heartbeat 拡張 | `prevented_count` | agent→server | 直近のブロック件数(可視化用) |

サーバ側 DB/管理画面に「prevention 有効エンドポイント率」「直近ブロック件数」を出すと、商用上の差別化(=「止められるEDR」)が定量的に見える。

---

## 6. 互換性とフォールバック（マトリクス）

| 環境 | LSM | 挙動 |
|---|---|---|
| kernel **≥5.13** + `lsm=bpf` + BTF | ✅ | `enforce`：観測+実行前防御+改ざん防止（付録A-1 で下限確定） |
| kernel ≥5.8 + BTF, LSM 無効 or 5.8〜5.12 | △ | `observe`：観測+事後 kill（現状同等） |
| 旧 kernel / BTF 無し / コンテナ制限 | ✗ | `poll`：/proc ポーリング |

- **縮退は静かに行わず必ず heartbeat で申告**（[[project_tech_debt_ledger]] の「no silent caps」方針）。
- コンテナ/クラウドマネージド(EKS等)では LSM ブートパラメータを変えられないことが多い → ドキュメントで「prevention は LSM 有効なノード限定」と明記。

---

## 7. 段階的ロードマップ（PR 単位）

各フェーズは独立してマージ可能・ロールバック可能に分割。`enforce` を有効化する前に必ず `audit` 計測フェーズを挟む。

| Ph | 内容 | 成果物 | リスク |
|---|---|---|---|
| **0** | 実現可能性 PoC | RHEL10.1/Ubuntu22.04 で BPF LSM `bprm_check_security` を attach し、固定パスの execve を `-EPERM` で拒否する最小 `.bpf.c` + ローダ。`lsm=bpf` 設定手順を [[ETW検証ランブック]] 相当の Linux ランブックに記録 | 低（隔離環境） |
| **1** | 能力検出 + モード申告 | 起動時に LSM/BTF/kernel を検査し `enforce/observe/poll` を決定、heartbeat 申告。**この時点では拒否しない**（検出のみ） | 低 |
| **2** | prevention(audit) | `prevention_lsm.bpf.c`(execve/connect)、BPF マップ、`apply_prevention_policy` コマンド、policy.Manager 連携。**audit モードのみ**（ブロックせずアラート） | 中 |
| **3** | prevention(enforce) | テナント/ポリシー単位で enforce 昇格、fail-open 既定、ブロック件数可視化。誤検知を audit 実測で確認後に解放 | **高**（業務影響） |
| **4** | tamper(警告) | `task_kill`/`ptrace`/agent ファイル保護フックを **audit**（拒否せず警告ログ） | 中 |
| **5** | tamper(enforce) | kill 拒否→削除拒否の順で段階有効化。`disarm_tamper_protection` 経路、watchdog によるフェイルセーフ確認 | **高**（自滅リスク） |
| **6** | ビルド/配布整備 | bpf2go 生成物の CI 統合 or コミット運用（[[project_tech_debt_ledger]] の Linux eBPF 未完成課題と合流）、`prevention` build tag、署名 | 中 |

> 既存 eBPF 観測の「bpf2go 生成物が CI 未統合」という負債(P4-2)を Ph6 で合流解消する。prevention を入れるなら生成物のビルド経路確立は不可避。

---

## 8. リスクと緩和

| リスク | 緩和策 |
|---|---|
| **誤ブロックで業務停止** | fail-open 既定 + audit 必須 + テナント単位段階昇格 |
| **tamper で agent 自滅 / OS ロック** | BPF link を agent fd ライフタイムに紐付け（pin しない）+ watchdog + 段階導入（警告→kill拒否→削除拒否） |
| **`lsm=bpf` 要再起動で常時オン不成立** | 縮退モードを正式サポート、能力を可視化、ドキュメント明記 |
| **カーネルバージョン断片化** | CO-RE(BTF) 前提、検出ベースで機能を出し分け、対応カーネル表を維持 |
| **LSM フックの性能劣化** | カーネルは O(1) 照合のみ、複雑判定はユーザーランド、レイテンシ計測 |
| **正規運用(更新/停止)を阻害** | `disarm_tamper_protection` 経路で正規操作を明示的に通す |
| **コンテナ/マネージド環境で不可** | ノード限定機能として割り切り、ドキュメント化 |

---

## 9. テスト計画

- **単体**: 能力検出ロジック、ポリシー→BPFマップ反映の差分計算、コマンド dispatch（既存 `response_test.go` 拡張）。
- **カーネル統合（CI外/専用VM）**: `lsm=bpf` を有効化した VM で
  - 既知の禁止パス execve がブロックされる（enforce）
  - audit モードでは通るがアラートが立つ
  - agent への `kill -9`(非認可)が拒否される
  - `disarm` 後は正規停止が通る
  - agent クラッシュ時に保護フックが自動デタッチされ OS が操作可能（フェイルセーフ）
- **性能**: execve レイテンシ p99、ビルド回帰ベンチ。
- **第三者指標への布石**: enforce 化後は **MITRE ATT&CK Evaluations** 想定の攻撃チェーン（少なくとも Atomic Red Team の Linux test）で prevention 実効を測る。

---

## 10. 将来：Windows / macOS

Linux で機構と運用（audit→enforce 段階、ポリシー経路、可視化）を確立してから横展開する。

- **Windows**: prevention は **minifilter ドライバ(FltRegisterFilter) + WFP コールアウト**、tamper は **PPL(Protected Process Light) + ELAM**。**カーネルドライバ署名(EV証明書 + WHQL/Attestation Signing)が必須**で難易度・コスト最大。Linux で固めた「ポリシー型・audit/enforce 段階・heartbeat 申告」をそのまま移植する設計にしておく。
- **macOS**: **Endpoint Security Framework(ESF)** の `ES_EVENT_TYPE_AUTH_*`(authorization イベント)で実行前拒否。System Extension + Apple の Endpoint Security entitlement 申請が必要。tamper は SIP/TCC に依存。

→ **§5 のコマンド/ポリシー型・モード申告は OS 非依存に設計**し、各 OS は「実装層」だけ差し替える（既存の collector/response の OS 分離と同じ構造）。

---

## 付録A：決定事項（2026-06-19 確定）

実装前に詰めるべき4点を以下のとおり確定した。

1. **対象カーネル下限 = enforce は 5.13+ に絞る**
   理由: 5.7〜5.12 は BPF LSM が動くものの `bpf_d_path` 等のヘルパや CO-RE 周りが不安定で、execve ホットパスで踏むと回帰特定が困難。安定とサポート工数を優先。観測(`observe`)は従来どおり 5.8+、それ未満は `poll` 縮退。enforce 対応カーネル表をドキュメントで維持する。

2. **fail-open を既定とする（fail-close は opt-in）**
   理由: 商用初期は可用性優先。誤ブロックで業務停止する事故の損失が、初期段階での見逃しリスクを上回る。高セキュリティ要件テナントのみ明示設定で fail-close へ。enforce 昇格前の audit 実測を必須化することで見逃しリスクを補償する。

3. **tamper の正規停止 = サーバ指令(`disarm_tamper_protection`)を主経路、ローカルはワンタイムトークンを退避手段として併設**
   理由: マルウェアに乗っ取られたローカル管理者から守るのが目的なので、通常停止/更新/アンインストールは**サーバ指令必須**を原則とする。ただしサーバ到達不能(オフライン/隔離中)に正規運用が詰むのを避けるため、**インストール時に生成しオフライン保管するワンタイム disarm トークン**を退避経路として用意（使用で無効化・監査ログ記録）。

4. **検証環境 = 都度構築（常設しない）**
   理由: コスト最適化。`lsm=bpf` 有効化は GRUB 設定＋再起動の使い捨てVMで足り、常設は不要。Ph0/Ph2 等のカーネル統合テスト時に EC2 上で `lsm=bpf` 有効 VM をスポット起動 → 検証 → 破棄する手順を Linux カーネル防御ランブック(新設予定)に記録する。[[project_ci_billing_block]] の予算事情とも整合。

---

## 付録B：Ph6 配布設計（2026-06-19, Ph0〜Ph5 実機実証後に策定・未実施）

Ph0〜Ph5 で prevention/tamper は実機実証済みだが、すべて `prevention` build タグ＋未コミット生成物のため、**本番エンドポイントには載っていない**。Ph6 はこれを配布する。

### B-0. 現状（実コードで確認）

- **配布中の Linux agent はポーリングのみ**: `.github/workflows/ci.yml` の Agent Build は `go build ./cmd/agent/...`（**タグ無し**）。eBPF 観測も prevention/tamper も入っていない（`-tags ebpf` ですら未配布）。
- **committed bpf2go 生成物は `processmonitor_bpf*` のみ**。prevention/tamper（`preventionlsm_bpf*` / `tamperlsm_bpf*`）は未コミット＝EC2 で都度生成していた。
- `CGO_ENABLED=0`。cilium/ebpf は純 Go なので CGO 不要（CO-RE の .o さえあれば clang 不要でビルド可）。

### B-1. 生成物のコミット（clang 無しビルドの鍵）

`clang+BTF` ホスト（RHEL EC2）で1回生成し、以下を**コミット**する（CO-RE = カーネル非依存で可搬。processmonitor の #192/#193 と同方式）:

```
agent/internal/platform/linux/preventionlsm_bpfel.go / .o / _bpfeb.go / .o
agent/internal/platform/linux/tamperlsm_bpfel.go / .o / _bpfeb.go / .o
```

→ これで CI（ubuntu）/ Windows クロスでも `go build -tags "ebpf prevention"` が clang/vmlinux.h 無しで通る。実機ビルド（Ph2-Ph5）で「processmonitor 既コミット＋prevention/tamper 都度生成」で成立したことから、`ebpf prevention` タグに必要な生成物はこの2種で十分と確認済み。

### B-2. ビルド変種戦略（決定）

graceful degradation（eBPF不可→ポーリング / LSM不可→observe / enforceは既定off）により、prevention 入りバイナリは**どの Linux でも安全に動く**（実機で fail-open 実証済）。それでも段階導入の慎重さを優先し:

- **第1段（Ph6a）= 別アーティファクト `edr-agent-linux-amd64-ebpf`** を `-tags "ebpf prevention"` で追加ビルドし併配布。lsm=bpf カーネルの顧客が opt-in。既存のポーリング版 `edr-agent-linux-amd64` は不変（後方互換）。
- **第2段（Ph6b）= 既定化**: フリートで mode 申告（Ph1）と audit 実績を確認後、Linux 既定ビルドを `-tags "ebpf prevention"` に切替（1バイナリで最良機構を自動選択）。

理由: 一気に既定化すると全 Linux 顧客で eBPF コードパスが動く（表面積増）。別アーティファクト先行で早期採用者が検証 → 実績後に既定昇格、が audit→enforce と同じ安全思想。

### B-3. ci.yml 変更（B-1 後に実施）

Agent Build matrix に Linux eBPF 変種を追加（`CGO_ENABLED=0`・committed .o ゆえ clang 不要）:

```yaml
# 追加マトリクス例
- goos: linux
  goarch: amd64
  suffix: "-ebpf"
  tags: "ebpf prevention"
```
ビルドステップを `go build -ldflags="-s -w" ${{ matrix.tags && format('-tags "{0}"', matrix.tags) }} -o edr-agent-${{ matrix.goos }}-${{ matrix.goarch }}${{ matrix.suffix }} ./cmd/agent/...` 相当に（タグ有無を分岐）。生成物 `edr-agent-linux-amd64-ebpf` を downloads/ へ配信。**Actions 必要＝予算復旧後**。

### B-4. 生成物の再生成ワークフロー（保守）

- `vmlinux.h` は巨大・ホスト依存ゆえ**コミットしない**（生成時のみ必要）。
- `*_lsm.bpf.c` を変更したら、clang+BTF ホストで `go generate ./internal/platform/linux/...`（または bpf2go 直叩き）して `*_bpf*.{go,o}` を**同一 PR で再コミット**。.bpf.c と .o の同期を PR レビューで担保。
- 落とし穴: .bpf.c 編集後に再生成し忘れると stale .o。CI で自動再生成→diff 検知は clang 必要（コスト）なので当面は運用ルールで担保。

### B-5. 顧客環境での安全性・ロールアウト

- prevention/tamper とも **既定 audit / fail-open**。enforce は `EDR_PREVENTION_ENFORCE=1` / `EDR_TAMPER_ENFORCE=1` の per-endpoint opt-in。配布だけでは一切ブロックしない。
- tamper enforce 時の正規停止は **SIGUSR1 disarm**（Ph5 実装済）。サーバ指令 disarm（`disarm_tamper_protection` gRPC、付録A-3）は将来拡張。
- ロールアウト順: ebpf 変種配布 → Ph1 mode 申告でフリートの enforce 可能率を可視化 → audit ルールで誤検知計測 → テナント単位で enforce 昇格。
- フェイルセーフ: BPF link 非 pin ＝ agent 終了で自動デタッチ（OS ロックなし、実機確認済）。systemd 再起動で再 arm。

### B-6. Ph6 実施チェックリスト（予算復旧後）

1. RHEL EC2 で prevention/tamper 生成物を生成しコミット（B-1）
2. ci.yml に linux-ebpf 変種追加（B-3）→ CI 緑 → `edr-agent-linux-amd64-ebpf` 配信
3. lsm=bpf 顧客/検証機へ ebpf 変種を配置 → mode 申告・audit を確認
4. （別途）Ph1 server 反映 = `docker.yml` で migration 268（protection_mode 列）→ 管理画面で可視化
5. 実績後、既定化（Ph6b）と enforce 昇格を判断
