# baseline 未知プロセス FP の実行元ゲート化 / Linux 永続化 FIM とテレメトリ drop 実測 — 2026-07-07 セッション総括

[検知率向上_20260703_fieldsupportロングテール消化.md](検知率向上_20260703_fieldsupportロングテール消化.md) 以降の続報。Windows 側の
容易な recall レバーが枯渇し、伸びしろは Linux に移った、という前提での作業。本セッションは 3 テーマを扱った:

1. **baseline 未知プロセス検知の FP 根治**（名前ではなく「実行元ディレクトリ」で発火）— [PR #420](https://github.com/kizashi-labs/kizashi/pull/420)（main マージ済 `d4679d1b`）
2. **Linux プロセステレメトリの間欠 drop の実測**（②）— eBPF ビルドでは drop ゼロを定量確認
3. **Linux 永続化 FIM の死角**（①）— /home ユーザー永続化は [PR #423](https://github.com/kizashi-labs/kizashi/pull/423)、cron/ld.so.preload/rc.local 等の system 面は [PR #426](https://github.com/kizashi-labs/kizashi/pull/426)（いずれも並行セッション・main マージ済）でカバーされ、**残った `/etc/systemd/system`（システムサービス永続化 T1543.002）**を [PR #431](https://github.com/kizashi-labs/kizashi/pull/431) で補完

> **注記（並行セッションとの衝突）**: 本セッション中、①②の推奨の多くを別セッションが並行実装し main へ先行マージした
> （/home FIM = PR #423、system 永続化 file_event + **背圧修正** = PR #426）。着手前に origin/main の重複確認が必須という
> 教訓。結果として本セッション固有の成果は **PR #420（baseline FP）**・**drop の定量実測**・**PR #431（`/etc/systemd/system` の残穴）** に収斂した。

---

## 0. 要約（TL;DR）

- **baseline FP**（PR #420, 本セッション固有）: 行動ベースライン「通常見られないプロセス」検知が良性短命ツールで氾濫
  （実測 **3,586 件 / 3 agent / 771 個の異なる process 名 / 全 sev4**）。真因は上位 50 プロセスしか baseline に持たないこと +
  `process_name` が `comm`（15 byte 切り詰め）で identity 不適。**「名前」でなく「実行元の場所」でゲート**し、良性裾野を
  根治しつつ `/tmp/dropper`・`/tmp/xmrig`・`/tmp` 内 kworker 偽装（T1036）等の実ドロップは発火継続。
- **② テレメトリ drop**: eBPF エージェントは **0 drop**（短命 40/40・バースト 700/700 捕捉）。間欠 drop の 2 機序のうち
  **背圧（silent drop）は PR #426 が `sendProcEvent` で根治済**、残るは非 eBPF ビルドの **200ms ポーリング粒度未満の
  短命プロセス消失**のみ。
- **① 永続化 FIM**: /home（PR #423）+ cron/ld.so.preload/rc.local/profile.d（PR #426）で大半カバー。**live 検証**で
  authorized_keys 改ざん→**T1098.004 sev8**、.bashrc→**T1546.004** 発火を確認。残った **`/etc/systemd/system`
  （システム systemd ユニット= root 永続化 T1543.002）** を PR #431 で補完（agent 監視 + migration 312 の file_event ルール）。

---

## 1. baseline 未知プロセス FP を実行元ディレクトリでゲート（PR #420）

### 問題
`server/internal/behavioral/baseline.go` の `CheckProcessAnomaly` は履歴（`TypicalProcesses`）に無いプロセス名を
sev4 アラート化していたが、`BuildBaseline` は `process_name` の**上位 50 件しか保持しない**ため、多目的 Linux ホストの
短命ユーティリティの**無限の裾野**が FP 化する。さらに `process_name` は Linux `comm`（15 byte 切り詰め）で、
`landscape-sysin`（実体 `/usr/bin/python3.10`）等 identity 不適。`chmod`/`rm` 等は LOLBin 悪用の可能性があり
**名前 allowlist 不可**。

### 対応：名前でなく「場所」
`CheckProcessAnomaly(agentID, processName, imagePath)` に生 `image_path` を渡し、**未知プロセスが疑わしいドロップ先
（`/tmp`・`/var/tmp`・`/dev/shm`・`/run/user`・`/home`・`/root` 等、Windows は Temp/AppData 等）から実行された場合のみ
発火**（`isSuspiciousExecPath`）。システムパス由来・解決不能（bare comm・切り詰め `/usr/bin8`・コンテナ `/moby`・`/runc`・
`/proc/self/fd`）は**すべて抑制**。正規化済み `flat["Image"]` でなく**生の `image_path`** を使う点が肝。

### 設計判断（実データ裏取り）
- would-FIRE 集合に実攻撃シミュレーション（`/tmp/dropper`・`/tmp/xmrig`・`/tmp/…/kworker` 偽装 = T1036）が正確に含まれ、
  `/proc/self/fd`（11 万件）・`/moby`・`/runc`・切り詰め `/usr/bin8` のノイズは全抑制。
- **denylist（疑わしい先で発火）を採用**。「未知の絶対パスルートで発火」は不採用＝`/detection-server`・`/go-build*` 等の
  雑多な良性ルートが新 FP 源になるため。severity=4 据え置き（`AUTO_ISOLATE_MIN_SEVERITY=9` 未満）。

### 検証・掃除
- **live A/B**（`/bin/sleep` コピーを 3 秒生存させ捕捉）: `/tmp/x` 発火・`/tmp/kworker` 偽装発火・`/usr/local/bin/x`
  （同一未知バイナリ）抑制を実証。デプロイ後 3 分の良性 churn（1000+ proc/5min）で system-path FP **ゼロ**。
- 履歴 FP を **3,463 件 DELETE**（疑わしいパス実行歴を持たない=新ロジックが抑制する対象）、実ドロップ由来 **171 件保全**。
  副次: baseline FP（T1059）掃除で旧 per-technique 相関の**空インシデント churn も停止**（空 1,272 + 旧 correlation_groups 1,270 掃除）。

---

## 2. ② Linux プロセステレメトリの間欠 drop 実測

収集経路は `agent/internal/platform/linux/process_ebpf.go`。出荷デフォルト（`-tags ebpf` 無し）は
`runEBPFProcessMonitor` が stub で必ず失敗し **`pollProcFS`（/proc を 200ms 間隔で差分ポーリング）へフォールバック**する。

### drop の 2 機序と現状
1. **構造的（ポーリング粒度）**: 200ms 未満で終了する短命プロセスは PID がスナップショットに現れず**恒久的に不可視**。
   → **非 eBPF ビルドに残る**（eBPF ビルドでは exec を同期捕捉するため解消）。
2. **バックプレッシャ（silent drop）**: 送信チャネル満杯時の `select{case out<-evt: default:}` 破棄。
   → **PR #426 が `sendProcEvent`（blocking + ctx 対応）に統一して根治済**。

### 実測（eBPF ビルド＝計測 EC2 で稼働中、kernel 6.8）

| テスト | 結果 |
|---|---|
| 短命（瞬時終了 `/bin/true` コピー）40 プロセス | **40/40 捕捉（0 drop）** |
| バースト 700 プロセス（500 連続 + 200 並列） | **700/700 捕捉（0 drop）** |

→ eBPF ビルドはテレメトリを一切取りこぼさない（`.o` 鮮度修正後の健全性を実証。[Linux-eBPF短命プロセス検知の修正と実機検証.md](Linux-eBPF短命プロセス検知の修正と実機検証.md) §9/§10）。
**残るのは非 eBPF ビルドの構造的 drop のみ** → 根治は「標準を eBPF ビルドに昇格」（標準 `edr-agent-linux-amd64` は
`server/Dockerfile` で `-tags ebpf` 無し）。

---

## 3. ① Linux 永続化 FIM — /home（#423）・system 面（#426）と残穴（PR #431）

FIM は `agent/internal/collector/fim_collector.go` の **SHA-256 ポーリング**（60s、glob 対応）。`fim_change` の `path` は
サーバ側で `TargetFilename` に alias される。

### live 検証（既存 + 並行実装の動作確認）
| 改ざん | 検知 | severity |
|---|---|---|
| `/home/ubuntu/.ssh/authorized_keys` | T1098.004 SSH authorized_keys への不審な書き込み | **8** |
| `/home/ubuntu/.bashrc` | T1546.004 Shell Startup File Modification | 4 |

/home 永続化の死角は既に塞がれ検知が上がっている（求めた "after" を実証）。

### 残穴 = システム systemd（PR #431）
PR #423/#426 は **user systemd（`~/.config/systemd/user`）と cron/ld.so.preload/rc.local/profile.d** をカバーしたが、
**システムレベルの `/etc/systemd/system`（root サービス永続化 T1543.002）は死角**のまま残っていた。PR #431 で:
- **agent**（`fim_collector_linux.go`）: `/etc/systemd/system`（再帰）を `defaultFIMRules` に追加。
- **server**（`migrations/312`）: systemd ユニット直接書き込みの file_event ルール（既存 T1543.002 は
  process_creation=systemd-run のみ。PR #426 の migration 311 と同じ流儀の DB ルール）。

> **検証状況**: システム永続化パスへの書き込みは FIM イベントとして確実にサーバ到達（agent 完全動作）。
> `/etc/ld.so.preload`→T1574.006 sev7 / `/etc/rc.local`→T1037.004 sev6 は PR #426 の migration 311 ルールで発火を実機確認。
> systemd file_event ルール（PR #431）の実発火は恒久デプロイ後に確認予定（migration 適用が前提。EC2 の
> detection Docker ビルド未反映問題により本セッションでは未確認）。

---

## 4. 教訓

- **並行セッションの衝突を着手前に確認**: 本セッションは ①② の推奨の大半が別セッション（PR #423/#426）に先取りされた。
  origin/main の重複・migration 番号衝突を着手前に確認する。
- **sigma ルール（builtin backtick raw string）はコンパイル後バイナリで grep 不能**（本番で発火中の文字列すら「MISSING」
  と出る）。ルール有無はバイナリ文字列でなく実発火 or ロード数で確認する。
- **detection の Docker ビルドが新ソースなのに未反映バイナリを生成する現象が再発**（`--no-cache`・直接 go build でも）。
  反映は稼働バイナリの実挙動で検証。
- ホットスワップ検証は対象を数秒生存させる（`/bin/true` 等の瞬時終了は非 eBPF ビルドで非捕捉）。

---

## 関連ドキュメント
- [Linux-eBPF短命プロセス検知の修正と実機検証.md](Linux-eBPF短命プロセス検知の修正と実機検証.md) — ② の前提（eBPF drop 修正・`.o` 鮮度）と本セッションの drop 実測（§10）
- [ATT&CK検知率測定計画.md](ATT&CK検知率測定計画.md) — 測定の枠組み
- [検知ルールの二重管理とデプロイ.md](検知ルールの二重管理とデプロイ.md) — builtin `[Sigma]` / curated `[SIGMA]` の二系統
- [技術的負債と改善計画.md](技術的負債と改善計画.md) — P4-2（Linux eBPF 出荷ビルド・背圧修正 #426）
