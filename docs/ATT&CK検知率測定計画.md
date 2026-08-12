# ATT&CK 検知率 自己測定計画書

本書は Kizashi の検知能力を **「他社 EDR と比較可能な定量スコア」** として自己測定するための計画書である。
既存の [マルウェア検証計画.md](マルウェア検証計画.md)（シナリオ A〜G）が「検知できるか（YES/NO）」を確認する手順書であるのに対し、本書はその上位に立ち、**Atomic Red Team を実行エンジンとして MITRE ATT&CK Evaluations と同じ採点方式で検知率(%)を算出する** ことを目的とする。

> ⚠️ すべて **隔離された検証用 VM** で実施する。本番ホスト・業務端末では絶対に実行しない。実マルウェア検体（VirusTotal / MalwareBazaar 等）は使用せず、**Atomic Red Team の振る舞いシミュレーション**と EICAR に限定する。

---

## 0. なぜこの測定が必要か

現状「実機検証済み」と言えるのは **単一テレメトリが拾えること**（`etw-verify` の process/network/dns/image_load/script PASS）まで。
これは ATT&CK Evaluations でいう **可視性(Telemetry)** の一部に過ぎず、「攻撃テクニックをアラートとして検知できた率」「実行前に防御できた率」「誤検知率」という、**他社と比較するときに必ず聞かれる数字**が未測定である。本計画はこの3つの空白を埋める。

---

## 1. 測定の物差し（採点ルーブリック）

MITRE Engenuity ATT&CK Evaluations の検知カテゴリに準拠し、各テクニック実行に対して以下のいずれか1つを付与する。**上位ほど高評価**。

| ランク | カテゴリ | 定義 | 本製品での判定根拠 |
|---|---|---|---|
| 0 | **None** | 何も記録されない | events にも alerts にも該当なし |
| 1 | **Telemetry** | 生イベントは記録されたがアラート化されない | `events` に該当プロセス/ネット/DNS等あり、`alerts` なし |
| 2 | **General** | 不審と判定しアラート化したが technique 未特定 | `alerts` あり・`technique` 空 or 汎用 |
| 3 | **Tactic** | ATT&CK の戦術(Tactic)レベルまで特定 | `alerts.technique` が戦術一致 |
| 4 | **Technique** | ATT&CK の technique ID まで特定 | `alerts.technique` が T番号一致 |
| ★ | **Blocked**（防御） | 実行そのものを阻止 | enforce モードで exec 拒否 / プロセス kill / 隔離発火 |

防御(Blocked)は検知カテゴリと**直交**する別軸として記録する（ATT&CK Evals の Protection 相当）。

---

## 2. 算出する KPI

1テストバッテリー（N テクニック）実行に対し、以下を算出する。

| KPI | 定義 | 目標(初期ゲート) |
|---|---|---|
| **可視性率 (Visibility)** | rank≥1 のテクニック数 / N | ≥ 90% |
| **検知率 (Detection)** | rank≥2 のテクニック数 / N | ≥ 70% |
| **解析検知率 (Analytic)** | rank≥4（Technique 特定）/ N | ≥ 50% |
| **防御率 (Block)** | Blocked テクニック数 / 防御対象テクニック数 | ≥ 60%（enforce 時） |
| **MTTD** | 実行時刻→アラート生成時刻の中央値 | ≤ 60 秒 |
| **誤検知率 (FP)** | 正常業務24hでの誤アラート件数 | ≤ 3 件/24h |

> これらは「他社 EDR の評価記事」と同じ語彙なので、**そのまま比較表に並べられる**。

---

## 3. テストハーネス構成

```
┌─────────────────────────┐        ┌──────────────────────────┐
│  攻撃側 (被験 VM)         │        │  Kizashi Server (EC2)   │
│  - Atomic Red Team       │ events │  - Ingestion (gRPC)       │
│    (Invoke-AtomicRedTeam)│───────▶│  - Detection Engine       │
│  - Kizashi Agent       │ alerts │  - REST API (/api/v1)     │
│    (全ETW/eBPF opt-in)   │        └──────────────┬───────────┘
└─────────────────────────┘                       │
                                                   ▼
                                      ┌──────────────────────────┐
                                      │ 採点スクリプト (scorer)   │
                                      │  実行ログ(techID,時刻) と │
                                      │  alerts/events を突合し   │
                                      │  rank/KPI を算出          │
                                      └──────────────────────────┘
```

### 3.1 攻撃側（被験 VM）
| 項目 | Windows | Linux |
|---|---|---|
| OS | Windows Server 2022 / Win11 22H2 (EC2) | RHEL 10.1 / Ubuntu 22.04 (EC2) |
| 実行エンジン | [Invoke-AtomicRedTeam](https://github.com/redcanaryco/invoke-atomicredteam) | 同 (bash/python tests) |
| エージェント設定 | `EDR_AGENT_ETW=1`（process/network/dns/image_load/script/auth 全有効） | `-tags ebpf` ビルド + `EDR_PREVENTION_ENFORCE`（防御フェーズのみ） |
| 競合排除 | `Set-MpPreference -DisableRealtimeMonitoring $true` | 他 HIDS 停止 |

### 3.2 採点側（scorer）
- サーバ REST API からテスト窓内の `alerts` と `events` を取得し、Atomic の実行ログ（テクニックID + 開始/終了時刻）と突合。
- 実装雛形は §6。

---

## 4. 対象テクニックセット（初回スコープ）

実装済み検知器（17 プロセスチェーン + `attack_eval_test.go` の単一イベント + Sigma + IOC）から逆算し、**「取れるはずのテクニック」を最優先で測る**。これにより実装と測定のギャップ（＝隠れ MISS）が可視化される。

### 4.1 Tier 1 — 実装済み・Technique 特定が期待できる（必達）
| ATT&CK | テクニック | 対応検知器 | Atomic Test 例 |
|---|---|---|---|
| T1059.001 | PowerShell | Sigma + chain-T1059.001 | T1059.001-1/2 |
| T1003.001 | LSASS Memory | chain-T1003.001 (comsvcs) | T1003.001-1 |
| T1490 | Inhibit Recovery (vssadmin) | chain-T1490 | T1490-1 |
| T1562.001 | Disable Defender | chain-T1562.001 | T1562.001-x |
| T1547.001 | Run Keys 永続化 | chain-T1547.001 | T1547.001-1 |
| T1053.005 | Scheduled Task | chain-T1053.005 + 単一 | T1053.005-1 |
| T1218.011 | Rundll32 | chain-T1218.011 | T1218.011-x |
| T1021.001/002 | RDP / SMB 横移動 | chain-T1021.x | T1021.002-x |
| T1070.001 | Event Log クリア | 単一(wevtutil) | T1070.001-1 |
| T1071 | C2 (DNS/HTTP) | IOC matcher | T1071.004（test ドメイン） |
| (file) | EICAR | YARA | — |

### 4.2 Tier 2 — 単一イベントで Telemetry〜General が期待できる（ディスカバリ群）
T1033 / T1057 / T1082 / T1016 / T1018 / T1087.002 / T1518.001（whoami / tasklist / systeminfo / ipconfig / net view 等、`attack_eval_test.go` に対応あり）

### 4.3 Tier 3 — 未対応見込み（MISS を正直に記録する）
プロセスインジェクション T1055（メモリ検知 M1/M2 は audit のみ、未配布）、難読化 T1027 の深い変種、BYOVD、`image_load` サイドローディング T1574.002（実装はあるが採点未実施）等。**ここで出た MISS が次スプリントのバックログになる。**

> Tier 3 を測定対象から外さないこと。**「測らなかった項目」を成功率に含めないのが他社比較で最も誠実**。

---

## 5. 実行フェーズ

### Ph0: 環境準備 & FP ベースライン（0.5日）
1. 被験 VM に agent 配布（enrollment token）、ETW/eBPF 全 opt-in 有効化。
2. `etw-verify` を流し全テレメトリ PASS を前提条件として確認（[ETW検証ランブック.md](ETW検証ランブック.md)）。
3. **攻撃を一切行わず 24h 通常操作**（ブラウジング/Office/更新）→ `alerts` 件数を数える＝**FP ベースライン**。

### Ph1: 単一テクニック・バッテリー（1日）
1. Tier1+Tier2 の Atomic test を**1つずつ、間隔を空けて**実行。各実行の `(techID, 開始時刻, 終了時刻)` をログ。
2. 各 Atomic test の `cleanup` を必ず実行（永続化・サービス変更の原状回復）。
3. scorer で rank 付け → 可視性率/検知率/解析検知率/MTTD を算出。

### Ph2: マルチステップ・チェーン（1日）
1. 17 プロセスチェーンルールを狙い、**親子連鎖**を再現（例: winword→cmd→powershell→certutil）。Atomic を順次起動 or 専用スクリプト。
2. 単発では出ないが相関で出る検知（chain-*）の発火を確認 → **相関エンジンの実効性**を測る。

### Ph3: 防御(Block)モード測定（0.5日）
1. Linux: `EDR_PREVENTION_ENFORCE=1` で Tier1 の exec を流し、`exit 126`(EPERM) で阻止された率を測定（[Linuxカーネル防御検証ランブック.md](Linuxカーネル防御検証ランブック.md)）。
2. Windows: `winprev-poc -enforce` でプロセス生成ブロックを測定（[Windowsカーネル防御PoC手順.md](Windowsカーネル防御PoC手順.md)）。
3. 自動隔離: severity≥9 アラートで `AUTO_ISOLATE` が発火するかを1ケース実証。

### Ph4: 採点・スコアカード・他社比較（0.5日）
scorer 出力からスコアカード（§7）を生成し、公開されている他社 ATT&CK Evals 値と並べる。

---

## 6. 採点自動化（実装済みツール）

本計画の採点ツールは **実装済み**。雛形ではなく実際にビルド・実行できる。

### 6.1 構成
| 成果物 | パス | 役割 |
|---|---|---|
| **attack-scorer** | `agent/cmd/attack-scorer/`（Go） | runlog + サーバ API を突合し ATT&CK ランク/KPI を算出 |
| technique→tactic マップ | `agent/cmd/attack-scorer/tactics.go` | サーバ側に無いため内蔵（Tier1/2 を網羅） |
| **run-atomics.ps1** | `agent/scripts/run-atomics.ps1` | Atomic を順次実行し RFC3339 runlog を出力（Win/Linux 共用・pwsh） |
| run-atomics.sh | `agent/scripts/run-atomics.sh` | pwsh 不可環境向けの最小版（手動コマンド方式） |
| **Caldera アダプタ** | `agent/cmd/attack-scorer/caldera.go`（`-caldera` フラグ） | **MITRE Caldera 多段エミュレーション**のオペレーションレポート(JSON)を runEntry 化し、オペレーション単位で**チェーン採点**。`-runlog` の代替。MITRE ATT&CK Evaluations 受験前の自己測定。手順=[ops/Caldera多段エミュレーション採点.md](ops/Caldera多段エミュレーション採点.md)、取得+採点=`agent/scripts/run-caldera-score.sh` |

> **単発 vs 多段**: Atomic(`run-atomics`)=テクニック単発の被覆測定。Caldera(`-caldera`)=偵察→資格情報→横展開→C2 のような連鎖を実行し、`attack-scorer` のチェーン採点（ATT&CK Evaluations 形式の「段数/可視化/検知/防御/断ち切り」）で評価。両者とも同じ scorecard 出力・同じ定点観測ゲート(`-baseline`)に乗る。`-caldera`↔`-runlog` の採点同一性は同一チェーンの fixture で実証済み。

> サーバの実 API（`/api/v1/alerts` `/api/v1/events`、`{data,total,has_more}` ラッパー、`mitre_technique`/`ai_mitre_tags`/`created_at`(RFC3339)、`from`/`to`/`agent_id` フィルタ）に実装を合わせ済み。technique→tactic は ATT&CK Enterprise を内蔵マップ化（`tactics.go`）。

### 6.2 採点ランクの判定ロジック（実装どおり）
各 runlog 行 `(technique, start, end)` に対し、検知窓内で:
1. その窓・対象エージェントの **アラート**を走査し、`mitre_technique` / `ai_mitre_tags` の T番号が
   - **technique 一致**（完全一致、または片側が基底のみ＝`T1059.001`↔`T1059`）→ **Technique(4)**。
     **別サブテク同士（`T1059.001` vs `T1059.003`）は誤特定とみなし Technique にしない**（MITRE Evals 流の精度）→ 同一 tactic 共有で Tactic 止まり。
   - 同一 **tactic** を共有 → **Tactic(3)**
   - アラートはあるが technique 不一致/空 → **General(2)**
2. アラート無し → **events API の `total>0`** を確認し、あれば **Telemetry(1)**、無ければ **None(0)**
3. MTTD は General 以上の最初のアラートまでの実行開始差分（**非負のみ**記録。run 開始前に発火した
   相関アラートは「行動→検知の遅延」として意味を持たないため latency に含めない）。

検知窓の下限境界（commit `bd8a92a7`）:
- **単一技アラート**は前方窓 `[start, end+window]`（検知レイテンシ意味論＝アラートは行動に先行しない）。
- **相関アラート**（`ai_mitre_tags` が2件以上、例＝偵察バースト）は観測窓を1アラートに畳んで閾値到達時に
  一度発火するため、前後窓 `[start-window, end+window]` で双方向に加点する（MITRE Evals 流＝シナリオ中に
  技術を検知したか）。タグ一致は依然必須なので過剰加点はしない。
  > 実測補足: この双方向加点は、観測した実データ（§11/§12）では旧ロジックと同一結果＝実効 no-op だった
  > （バースト発火が run 開始後で前方窓に収まったため）。遅延発火する相関技を将来取りこぼさないための保険。

### 6.3 実行手順
```bash
# ① 被験 VM で Atomic 実行 → runlog 生成
pwsh ./agent/scripts/run-atomics.ps1 -Techniques T1059.001,T1003.001,T1490 -OutLog runlog.csv

# ② 採点（ビルド & 実行）
cd agent && go build ./cmd/attack-scorer
./attack-scorer -server https://<host> -token <JWT|edr_キー> \
                -runlog ../runlog.csv -window 120 -out scorecard.csv
```
- `-agent <id>` で突合対象エージェントを限定（複数台環境のノイズ排除）。
- `-insecure` は自己署名 TLS の検証環境のみ。
- 標準出力にスコアカード、`scorecard.csv` に個別結果（technique/rank/latency/根拠アラート）。
- **多段チェーン採点**: runlog に `scenario` 列があれば同名行を1チェーンとして段別採点＋連鎖断ち切り率を出す。`run-atomics.ps1 -Scenario <名>` / `run-atomics.sh out.csv <名>` で全技をタグ付け。
- **定点観測（回帰ゲート）**: `-baseline <前回scorecard.csv> -baseline-tol <pt>` で可視性/検知/解析検知率が baseline を許容幅超で下回ると **exit 3**。CI でルール増加・採点変更の退行を自動検出。
  ```bash
  ./attack-scorer ... -out today.csv -baseline docs/results/last.csv -baseline-tol 2
  ```

### 6.4 スモーク確認済みの挙動
- runlog CSV のヘッダ解決（列順不問）・RFC3339 / TZ無し時刻パース
- 測定期間の自動算出（最初の開始〜最後の終了+window）
- alerts のページング全件取得、events は `total` のみ取得（軽量）

> **将来の自動化**: `agent-ebpf.yml` と同様に `workflow_dispatch` で EC2 spot を起動 → run-atomics → attack-scorer → `scorecard.csv` を artifact 化（CI 上に実 Windows/Linux VM が無い制約は spot 起動で回避）。出力は `docs/results/attack-scorecard-YYYYMMDD.csv` に保存。

---

## 7. 成果物：スコアカード様式

```
=== Kizashi ATT&CK 検知率スコアカード (2026-XX-XX) ===
環境: Win2022 EC2 / agent vX.Y / ETW全有効
対象: Tier1+Tier2 = N techniques

  可視性率 (rank≥Telemetry) : 92%  (46/50)
  検知率   (rank≥General)   : 74%  (37/50)
  解析検知 (rank=Technique) : 54%  (27/50)
  防御率   (Blocked/対象)   : 63%  (12/19)   ※enforce
  MTTD (中央値)             : 41s
  FP (24h ベースライン)     : 2 件

  --- MISS 一覧（次スプリント候補）---
  T1055   Process Injection      : None      → メモリM1/M2配布で改善見込み
  T1574.002 DLL Side-Loading     : Telemetry → image_load 採点ルール未接続
  ...
```

### 他社比較欄（参考値・要出典明記）
| 指標 | Kizashi(実測) | 商用A | 商用B |
|---|---|---|---|
| Analytic Coverage | 54% | （ATT&CK Evals 公開値を出典付きで） | … |
| Block | 63% | … | … |

> 他社値は **必ず出典（ATT&CK Evaluations のラウンド名・年）を併記**。バージョン・対象テクニックが違えば厳密な等価比較にならない点も注記する。

---

## 8. リリースゲート（合格基準）

| # | 基準 | 閾値 |
|---|---|---|
| 1 | EICAR 検知 | Win/Linux 各 100% |
| 2 | Tier1 Technique 特定率 | ≥ 70% |
| 3 | 17 プロセスチェーン発火 | ≥ 15/17 |
| 4 | 応答アクション(isolate/kill/quarantine) | 各 OS 3/3 |
| 5 | 可視性率 | ≥ 90% |
| 6 | FP 率 | ≤ 3 件/24h |
| 7 | MISS 一覧の起票 | 全 None/Telemetry を負債台帳へ |

---

## 9. 注意・制約

- **実マルウェアは使わない**：Atomic Red Team の振る舞い再現 + EICAR のみ。C2 は test ドメイン/自前リスナに限定。
- **破壊的テストの原状回復**：永続化・サービス・レジストリ変更は Atomic の `cleanup` を必ず実行。スナップショットからの復元を推奨。
- **競合 AV の無効化**：Defender 等が先に殺すと「検知率」が汚染される。被験 VM では明示的に停止。
- **比較の誠実さ**：測定しなかったテクニックを分母から外さない。他社値は出典・ラウンド・対象差を明記。これを守らない比較は営業資料として逆効果。
- **ネットワーク隔離**：被験 VM は業務 LAN から分離。
- **⚠️ AUTO_ISOLATE による自滅に注意（2026-06-22 実際に発生）**：検知が正しく動くと、sev≥9（既定
  `AUTO_ISOLATE_MIN_SEVERITY`）のアラートで**自動隔離が発火し被験 VM のSSH/外部接続が遮断される**。測定時は
  ① `AUTO_ISOLATE_MIN_SEVERITY` を一時的に上げる/audit化、または ② sev9 未満に限定（reverse shell 等を除外）。
  復旧は別ホストから `POST /api/v1/agents/{id}/unisolate`（agentがサーバ接続を保てば隔離解除）、最終手段は
  EC2 再起動（iptables は揮発性）。

---

## 10. 既存ドキュメントとの関係

| ドキュメント | 役割 |
|---|---|
| [マルウェア検証計画.md](マルウェア検証計画.md) | シナリオ A〜G の **手順**（検知できるか YES/NO） |
| **本書** | A〜G を **定量化**し検知率(%)として採点・他社比較 |
| [Linux-eBPF短命プロセス検知の修正と実機検証.md](Linux-eBPF短命プロセス検知の修正と実機検証.md) | 初回実測で判明した eBPF 3層バグの根本原因・修正・再現手順 |
| [ETW検証ランブック.md](ETW検証ランブック.md) | Ph0 前提（テレメトリ疎通の確認） |
| [Linuxカーネル防御検証ランブック.md](Linuxカーネル防御検証ランブック.md) / [Windowsカーネル防御PoC手順.md](Windowsカーネル防御PoC手順.md) | Ph3 防御率測定の実行手順 |
| docs/技術的負債と改善計画.md | Ph4 で出た MISS の起票先（P4-2 に本件を記録） |

---

## 11. 実測結果（第1回・Linux, 2026-06-22）

RHEL 10.1 / kernel 6.12 EC2 上の Linux agent（eBPF版）で初回実測。**検知が「0」だった真因が
eBPF テレメトリのバグ（イベントが1970年タイムスタンプで保存され時間窓から不可視）だったことを突き止め、
修正後に検知が回復**した。詳細・再現手順＝[Linux-eBPF短命プロセス検知の修正と実機検証.md](Linux-eBPF短命プロセス検知の修正と実機検証.md)。

### 検知-positive バッテリー（短命プロセス, before/after）
| Technique | 修正前 | 修正後 |
|---|---|---|
| T1140 base64難読化実行 | None | **Technique**（SIGMA Base64 Obfuscation） |
| T1105 curl→/tmp ダウンロード | None | **Technique**（curl/wget Download to Temp） |
| T1166 SUID 付与 | None | **Technique**（SUID Bit Set） |
| T1059 /tmp 実行 | None | **Technique**（/tmp・/dev/shm 実行） |
| T1087.001 /etc/shadow 読取 | None | Telemetry（file_access系＝FIM連動が要） |
| T1059.004 reverse shell | （別途）| **Technique**（sev9→AUTO_ISOLATE発火で確認・自滅回避のため本バッテリーから除外） |
| **検知率** | **0/6** | **検知 4/5・解析検知(Technique) 4/5 = 80%（+reverse shell＝実効5/6）** |

### 重要な学び
- **「Linux検知0」は検知ルールの不足ではなく、eBPFプロセスイベントが1970年で保存され、時間窓クエリと
  検知の時間窓相関の双方から不可視だったため**。ルール・エンジン・自動対応は元から商用EDR同等に機能していた。
  **エージェントの可視性バグ1つが Linux 検知を丸ごと無効化**していた、という構図。
- **この種のバグは机上レビューでは見つからず、実機で攻撃を流して検知率を測って初めて露見した** ＝ 本測定基盤の最大価値。

### 残（未実測）
- Windows ETW 側の本測定（Tier1+2、Atomic フル）。Win box は時計ズレ要修正。
- AUTO_ISOLATE 無効化下での sev9 含む完全バッテリー（今回は自滅回避で reverse shell 除外）。
- MTTD / FP ベースライン / 防御率（enforce）。

## 12. 実測結果（第2回・Windows ディスカバリ, 2026-06-26）

Windows Server 2022 EC2 agent（`EC2AMAZ-EVVIB8T`）で、ディスカバリ・バーストを実機発火させて再測定。
**第1回（6-22）の Windows ディスカバリで唯一 MISS だった `net localgroup`（T1069.001）が Technique に
昇格することを実機で確認**した。

### ディスカバリ・バッテリー（8コマンド, before/after）
| Technique | コマンド | 第1回(6-22) | 第2回(6-26) |
|---|---|---|---|
| T1033 | whoami | Technique | Technique |
| T1087.001 | net user | Technique | Technique |
| **T1069.001** | **net localgroup** | **Telemetry（MISS）** | **Technique** |
| T1049 | netstat | Technique | Technique |
| T1018 | arp | Technique | Technique |
| T1016 | ipconfig | Technique | Technique |
| T1057 | tasklist | Technique | Technique |
| T1082 | systeminfo | Technique | Technique |
| **解析検知(Technique)** | | **7/8** | **8/8 = 100%（MISS なし・MTTD 3秒）** |

いずれも相関アラート「[BEHAVIORAL] 探索コマンドの短時間バースト（ディスカバリ）」1件が全技を担当
（MITRE Evals 流の相関加点）。

### 重要な学び — 真因はスコアラではなく検知コンテンツのタグ欠落
- T1069.001 の MISS は**スコアラのタイミング/窓の問題ではなく、バースト規則の `mitre_tags` に
  T1069.001 が無かったため**（`net localgroup` を発火はさせるが per-technique で加点されない）。
- **アラートの ATT&CK タグは生成時点で凍結**されるため、旧アラート（6-22 生成）を後から再スコアしても
  永久に救えない。新タグを反映するには**規則更新後に新規バーストを発火**させる必要がある。
- 修正の実体は検知コンテンツ側の **migration 273（PR#262）**＝バースト規則の `mitre_tags` に
  T1069.001 / T1007（System Service Discovery）/ T1135（Network Share Discovery）/ T1012（Query Registry）
  を補完するもの。ライブ rules API で適用済み（タグ保持・enabled）を確認のうえ、新規バーストで反映された。
- 並行して入れたスコアラ変更（相関アラートの前後窓・双方向加点, commit `bd8a92a7`）は、
  **旧スコアラを同じ新データで実行しても 8/8 Technique で同一結果＝観測データでは実効 no-op**
  だった（バースト発火が run 開始後で前方窓に収まるため）。本変更は遅延発火する相関技を将来
  取りこぼさないための防御的保険であり、今回の昇格要因ではない。

### 教訓（運用）
- **「タグを足したら直る」類の検知改善は、既存アラートの再スコアでは検証できない**。規則更新を
  デプロイ→新規イベントを流して新アラートを生成→そこで初めて測定する、という順序が必須。
- ライブ測定の最小手順（再現）: ① Win box で4種以上のディスカバリコマンドを60秒窓内に実行 →
  ② 新規バーストアラートの `ai_mitre_tags` を API で確認 → ③ 実行時刻で fresh runlog を作成 →
  ④ ローカルビルドの scorer を `-agent <id> -window 180` で実行。
- 接続・安全上の注意は [ETW検証ランブック.md](ETW検証ランブック.md) と
  [技術的負債と改善計画.md](技術的負債と改善計画.md) を参照（etw-verify は agent の ETW collector を
  落とすため測定中は実行しない／使用後の認証情報の即時削除）。
