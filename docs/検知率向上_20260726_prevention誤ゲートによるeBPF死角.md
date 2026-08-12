# 検知率向上（2026-07-26）: `prevention` 誤ゲートによる eBPF センサの死角

**実施日**: 2026-07-26（NetworkMonitor）／ 2026-08-01（FilelessMonitor・`release.yml`）
**対象**: Linux エージェント eBPF センサのビルドタグ
**関連 PR**: [#544](https://github.com/kizashi-labs/kizashi/pull/544)（NetworkMonitor、マージ済み `c559b13`）／ 本PR（FilelessMonitor + `release.yml` 退行の解消）
**状態**: report-only センサ2つとも修正済み。`-tags ebpf` でビルドする全経路の生成ステップを棚卸し済み（§5b）

---

## 0. 要約（TL;DR）

Linux の **network eBPF connect-tracer（kprobe `tcp_connect`）が、出荷される全ビルドで一度も動いていなかった**。

原因はビルドタグの誤ゲートで、consumer 側が `ebpf && prevention` を要求していたのに対し、`ci.yml` の標準 Linux
エージェントビルドは **`-tags ebpf` のみ**を渡す。結果、consumer が常にビルド対象外＝デッドコードとなり、
`network_ebpf_stub.go` 経由で **`/proc/net` ポーリングへサイレントフォールバック**していた。

`/proc/net/tcp` は**確立済みソケットしか列挙しない**ため、**閉じたポートへの接続試行が構造的に観測できない**。
これはポートスキャンの本質的シグネチャそのもので、サーバ側の `netScan`(T1046) スコアラは正しく実装されていたのに
**Linux では入力テレメトリが永久にゼロ**だった。

> 「検知ロジックは商用EDR同等に実装されていたが、**ビルドタグ1行がテレメトリ経路を丸ごと無効化していた**」
> という構図。[Linux-eBPF短命プロセス検知の修正と実機検証.md](Linux-eBPF短命プロセス検知の修正と実機検証.md)
> の §3③（ktime で全イベントが1970年）と同じ**「サーバに無い＝送っていない、ではなく経路が消えている」**類型。

さらに本件の調査中、**同じ誤ゲートが `fileless_runner.go`（T1620 Reflective Code Loading / T1055）にも
存在すること**を特定し、続けて是正した（§5）。その過程で **#544 が `release.yml` を壊していた**ことも
判明している（§5b）。

---

## 1. 症状

- Linux agent の出荷ビルド（`-tags ebpf`）で、**network eBPF センサが常に初期化されず** `/proc/net` ポーリングに落ちる。
- ログは無言（フォールバックは設計上の正常系として実装されているため）。テストも緑。
- サーバ側 `netScan`(T1046) は実装済み・単体テストも通るが、**Linux エンドポイントからは発火し得ない**。

## 2. 根本原因

| 層 | 実態 |
|---|---|
| consumer（`network_ebpf_loader.go` / `network_ebpf_bridge.go`） | `//go:build linux && ebpf && prevention` を要求 |
| 出荷ビルド（`ci.yml` agent-build, linux/amd64） | **`-tags ebpf` のみ**（ワークフロー自身のコメントに「strict superset・自動フォールバック」と明記） |
| 結果 | consumer が常に除外 → `network_ebpf_stub.go`（`!(ebpf && prevention)`）が有効 → `/proc/net` ポーリング |

**なぜ `prevention` が付いていたか**: [design/Linux改ざん防止と実行前防御設計.md](design/Linux改ざん防止と実行前防御設計.md)
§4.6 が、connect() テレメトリと fileless センサを「§2 の同一 eBPF 基盤で追加した report-only センサ」として
**`-tags "ebpf prevention"` ゲートで一括導入**したことに由来する。基盤を共有していたため同じタグに揃えたが、
**report-only センサは LSM/enforcement を持たないので `prevention` 層に属する必要がない**。

**ProcessMonitor が無事だった理由**: 同じ `ebpf` タグ配下で生成・消費されており、`prevention` の追加要求を
持っていなかった。誤ゲートは network monitor の consumer 2ファイルだけに付いており、**`-tags ebpf` 単独で
生成する既存の `go:generate` ディレクティブとも矛盾していた**（生成物は作られるが消費されない状態）。

## 3. 修正内容

| ファイル | 変更 |
|---|---|
| `agent/internal/platform/linux/network_ebpf_loader.go` | `linux && ebpf && prevention` → **`linux && ebpf`** |
| `agent/internal/platform/linux/network_ebpf_bridge.go` | 同上 |
| `agent/internal/platform/linux/network_ebpf_stub.go` | `linux && !(ebpf && prevention)` → **`linux && !ebpf`**（分割の整合維持） |
| `.github/workflows/ci.yml` | **NetworkMonitor の bpf2go バインディング生成ステップ**を Linux ビルド前に追加 |

NetworkMonitor の生成物は ProcessMonitor と違い**コミットされていない**ため、`-tags ebpf` の標準ビルドで
使うには生成が必要。生成ステップは `agent-ebpf.yml` の実績あるレシピ（bpftool を libbpf から make →
`/sys/kernel/btf/vmlinux` から `vmlinux.h` を生成 → bpf2go）をそのまま踏襲し、NetworkMonitor のみに絞って
**plain `-tags ebpf`** で生成している。

## 4. 検証

### ビルドタグ分割の網羅確認（4通り）

| ビルドタグ | loader / bridge | stub | 判定 |
|---|---|---|---|
| （なし） | 非活性 | 活性 | ✅ 排他 |
| `ebpf` | **活性**（← 本修正で有効化） | 非活性 | ✅ 排他 |
| `prevention` | 非活性 | 活性 | ✅ 排他 |
| `ebpf prevention` | 活性 | 非活性 | ✅ 排他 |

### 実施した検証

- **タグ無しの既定 Linux ビルド**: `GOOS=linux go build ./...` 成功（フォールバック経路の非退行）。
- **生成→ビルドの実CI実証**: 同一コードを含む deep-dive ブランチの CI run
  [#2031](https://github.com/kizashi-labs/kizashi/actions/runs/30145232527)（2026-07-25 05:08 UTC）で
  `Agent Build (linux, amd64, ebpf)` の **`Generate NetworkMonitor eBPF bindings` → `Build agent` がともに成功**。
  本作業環境（サンドボックス開発コンテナ）はカーネル BTF を持たないためローカルでは検証不能で、実CIで確認した。
- **`agent-ebpf.yml` の非退行**: 同ワークフローは生成・ビルドともに `-tags "ebpf prevention"` で一貫している
  （loader は `ebpf` を満たし、生成物は `ebpf && prevention` を満たす）ため影響しない。

> **補足（2026-08-01 追記）**: 2026-07-25 05:46 UTC から約6日間、リポジトリ全体で GitHub Actions が
> startup failure となり（main 自身も含む）#544 の CI を走らせられなかった。詳細＝
> [ops/CI負債_調査と是正.md](ops/CI負債_調査と是正.md) の該当追補。復旧後、#544 自身の CI
> run [#2124](https://github.com/kizashi-labs/kizashi/actions/runs/30704607581) で
> CI / Security Scan / Coverage の3ワークフローとも green を確認してマージ済み（`c559b13`）。

## 5. 【解消済み】同じ誤ゲートが FilelessMonitor にも存在した

`fileless_runner.go` も **`//go:build linux && ebpf && prevention`** で、同様に出荷ビルドではデッドコードだった。

- 実体は **純テレメトリ**: `link.Tracepoint("syscalls", "sys_enter_execveat", …)` と `sys_enter_memfd_create`
  のみ。LSM アタッチも `-EPERM` 返却もブロック判定も**一切ない**（`report-only` と設計書自身が明記）。
- 影響: **T1620 Reflective Code Loading / T1055（memfd・fd からのディスクレス実行）**の検知が、
  出荷ビルドの Linux エンドポイントでは発火しなかった。design §4.6 が「回避テストで MISS だった fileless 実行を
  根治」と記録している成果が、**標準配布には届いていなかった**。
  なお #511 のメモリスキャナ既定ON化は Windows の RWX/非バック領域スキャンで**別機構**のため、
  この Linux memfd 経路はカバーしない。

**修正（本PR）**: 誤ゲートは consumer 側3ファイルに跨っていたため一括で是正した。

| ファイル | 変更 |
|---|---|
| `internal/platform/linux/fileless_runner.go` | `linux && ebpf && prevention` → `linux && ebpf`（`go:generate` の `-tags` も同様） |
| `cmd/agent/fileless_linux.go` | 同上 |
| `cmd/agent/fileless_other.go`（no-op） | `!(linux && ebpf && prevention)` → `!(linux && ebpf)` |

## 5b. 【重要】PR #544 が `release.yml` を壊していた

FilelessMonitor の修正にあたり `-tags ebpf` でビルドする箇所を全数洗い直したところ、
**`release.yml` が生成ステップを持たないまま Linux を `-tags ebpf` でビルドしている**ことが判明した。
NetworkMonitor のバインディングは未コミットなので、**次の `v*` タグ push は
`undefined: NetworkMonitorObjects` でリリースビルドが失敗する**状態だった。

`release.yml` はタグ push 時のみ実行され **PR では走らない**ため、#544 の CI が全 green でも露呈しなかった。
本 PR で生成ステップを追加して解消（arm64 リリースに x86 向け BPF オブジェクトを積まないよう、
target arch を matrix に追従させている）。

### `-tags ebpf` でビルドする全箇所と生成ステップの対応（棚卸し済み）

| 箇所 | 生成ステップ |
|---|---|
| `ci.yml` agent-build (linux) | ✅ #544 で追加 |
| `ci.yml` agent-test | ✅ #544 で追加（当初漏れ→同PR内で修正） |
| `release.yml` build-agent (linux) | ✅ **本PRで追加（#544 の退行を解消）** |
| `agent-ebpf.yml`（`ebpf prevention`） | ✅ 既存（5 monitor すべて生成） |
| `agent-os-tests.yml` | 対象外（`""` / `esf` / `esf prevention` のみ） |
| `agent/Dockerfile` | 対象外（タグ無しビルド。§「意図的に変更していない点」参照） |

> **教訓**: ビルドタグを緩めると、**そのタグでビルドする全ての経路**が生成物を必要とする。
> PR で走らないワークフロー（`release.yml` のようなタグ駆動のもの）は CI が緑でも検証されないので、
> タグ変更時は grep で全経路を洗い出すこと。

### ビルドタグ棚卸し（`agent/internal/platform/linux/`）

`prevention` ゲートの妥当性を全数確認した結果:

| ファイル | タグ | 妥当性 |
|---|---|---|
| `prevention_lsm.go` / `prevention_runner.go` | `ebpf && prevention` | ✅ 妥当（LSM enforcement） |
| `tamper_runner.go` | `ebpf && prevention` | ✅ 妥当（改ざん防止 LSM） |
| `credaccess_runner.go` | `ebpf && prevention` | ✅ 妥当（LSM ベース） |
| `hostintegrity_runner.go` | `ebpf && prevention` | ✅ 妥当 |
| `fileless_runner.go` | ~~`ebpf && prevention`~~ → `ebpf` | ✅ 本PRで解消（report-only なのに prevention 層だった） |
| `network_ebpf_loader.go` / `_bridge.go` | ~~`ebpf && prevention`~~ → `ebpf` | ✅ PR #544 で解消 |
| `library_loader.go` | `ebpf && solib` | ✅ 妥当（独立 opt-in タグ） |

## 6. 教訓

- **report-only センサを enforcement のビルドタグに同梱しない**。基盤（eBPF）を共有することは、
  配布ゲート（`prevention`）を共有する理由にならない。テレメトリは標準ビルドに載せるのが既定であるべき。
- **「生成される」と「消費される」は別**。`go:generate` が `-tags ebpf` で生成物を作っていても、consumer 側の
  タグが厳しければコードは死ぬ。**生成タグと消費タグの一致を確認する**こと。
- **フォールバックがサイレントだと死角に気づけない**。`/proc/net` フォールバックは設計上の正常系として無言で
  動くため、ログにもテストにも異常が出なかった（network collector に至っては `err` を**完全に捨てて**いた）。
  → **2026-08-01 に是正済み**: `internal/telemetry` で各センサーの実効モードを記録し、降格時は理由と検知上の
  影響を Warn ログに出したうえで、heartbeat の `telemetry_mode` → `agents.telemetry_mode` → サマリAPI の
  `ebpf_effective_pct` まで配線した。**`protection_mode`（ホストの能力）とは別物**で、eBPF 可能なホストが
  タグ無しビルドでポーリングに落ちていても従来は `observe` としか見えなかった——それが本件の死角の直接の理由。
  詳細＝[技術的負債と改善計画.md](技術的負債と改善計画.md) P4-2。
- **カバレッジ監査は「ルールの有無」ではなく「テレメトリ到達性」で判定する**。`netScan` は存在し正しかったが、
  Linux では入力が永久にゼロだった。

---

## 7. 併走作業: PR #542 の整理

本セッションでは検知率改善の長期ブランチ `claude/detection-rate-deep-dive-gux8ck` を PR #542 として起票したが、
main との乖離が大きく**クローズし、本 PR #544 に必要分を切り出した**。

- main から **150コミット遅れ**（merge-base `1d6d9ea`）、`mergeable_state: dirty` で **27ファイルがコンフリクト**
- **157ファイル中 59ファイルが既に main 側に存在** — 並行して別 PR（#526, #540, #495, #499, #522 等）で
  同種の作業がマージされていた
- 依存関係の脆弱性修正3件は**すべて main に入済みで不要**だった:
  Go 1.26.5（GO-2026-5856 `crypto/tls` ECH）/ `golang.org/x/text` v0.39.0（GO-2026-5970, #526）/
  `otel/sdk` v1.43.0（GO-2026-5426, #540）
- **ブランチは削除していない**。main に無いブランチ固有ファイルが **98件**残っており（detection 24 /
  docs 19 / migrations 11 / agent platform 10 / agent cmd 9 / npfilter driver 4 / 計測スクリプト 4 / その他17）、
  main 最新への載せ替えと重複判定の上でテーマ別の小さい PR に分割し直す想定。

> **教訓**: 長期ブランチを走らせる間に同じ領域が別 PR で進むと、**重複と再作業が指数的に増える**。
> 検知率改善のような広範囲の作業は、テーマ単位で小さく main へ入れ続けるべきだった。

---

## 関連ドキュメント
- [Linux-eBPF短命プロセス検知の修正と実機検証.md](Linux-eBPF短命プロセス検知の修正と実機検証.md) — 同類型（可視性バグで検知が丸ごと無効化）の先行事例。§10 が「出荷デフォルトは非 eBPF ポーリング」の構造的 drop を記録
- [design/Linux改ざん防止と実行前防御設計.md](design/Linux改ざん防止と実行前防御設計.md) — §4.6 が本件の誤ゲートの出自
- [技術的負債と改善計画.md](技術的負債と改善計画.md) — P4-2 に本件を記録
- [ATT&CK検知カバレッジ監査.md](ATT&CK検知カバレッジ監査.md) — T1046 / T1620 のカバレッジ注記
- [ops/CI負債_調査と是正.md](ops/CI負債_調査と是正.md) — Actions 全体停止の記録
