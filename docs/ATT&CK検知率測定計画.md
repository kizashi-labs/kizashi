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
- **⚠️ 実行間隔 ＞ 採点窓 にする（2026-07-27 実際に誤測定）**：`-window` がテスト間隔より長いと、**後続テストの
  アラートが前のテストにも加算**される。実行全体170秒に対し `-window 180` で測ったとき、`echo` だけの
  T1059.004 が後続 T1105 の curl アラートで Technique 判定になった。間隔90秒・窓60秒のように
  **窓が次のテスト開始前に閉じる**設定にすること。同一ビルドで 76%→95%→100% と動いた実例がある。
- **⚠️ 相関検知器は疎な間隔で測ると構造的に過小評価される**：探索バーストは「窓5分・4種以上」で発火するため、
  90秒間隔では5分窓に 300÷90≒3.3種しか収まらず、閾値に届くかがタイミング次第になる。上記の「間隔＞窓」と
  **同時には満たせない**。探索系は**攻撃実態に近い密度（10–20秒間隔）で1シナリオとして**実行し、単発ルールで
  検知される技術のみを疎な間隔で個別評価すること。窓幅を測定の都合で広げるのは誤検知耐性の放棄であり不可。
- **⚠️ 測定中は `UEBA_ANOMALY_THRESHOLD=0`（必須）**：UEBA スタンドアロン異常アラートは `T1078` タグを持ち、
  T1078 は複数戦術に跨るため、`shareTactic()` により防御回避・権限昇格系のテクニックへ**無差別に Tactic 判定**を
  与える。閾値15で測ったとき16件の「検知」のうち6件がこの水増しだった。
- **⚠️ 測定スクリプトの二重起動でスコアが静かに壊れる（2026-07-27 実際に発生）**：同じ runlog へ2インスタンスが
  追記すると、行が交互に混ざり技術が重複記録され、**分母だけが増えた「それらしい数字」**（22件の実行に対し
  32件・84.4%）が出る。`run-atomics.sh` は排他ロックと runlog 検証（1技術1行・重複なし）で
  非ゼロ終了するようにしてあるが、**採点前に `対象テクニック: N` が実行件数と一致することを必ず確認**すること。
- **⚠️ サーバ再ビルド直後は測らない**：detection コンテナ再作成後はイベントのバックログ処理で数分の遅延が出る。
  アラートが採点窓を外れて**不当に低い**スコアになる。`SELECT now()-max(time) FROM events …` が数秒以内に
  なるまで待つ。

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

Windows Server 2022 EC2 agent（`WIN-ENDPOINT-01`）で、ディスカバリ・バーストを実機発火させて再測定。
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

---

## 13. 実測結果（第3回・Linux フルティア, 2026-07-27）

**初めて Tier 3（MISS 想定）を含めて測定した回**。第1回・第2回は Tier 1/2（本プラットフォームが最も厚い
discovery/実行系）のみで 100% が出ていたが、それは「得意領域だけを測った数字」であり比較には使えなかった。

### 条件

被験＝サーバ同居の Ubuntu 22.04（eBPF エージェント）/ 全22テクニック（Tier1:1, Tier2:11, Tier3:10）/
**間隔90秒・窓60秒**（§9 の「間隔＞窓」を満たす）/ `UEBA_ANOMALY_THRESHOLD=0` / 処理遅延1秒未満。

### 結果（同一条件で4回）

> ⚠ **下表は両列とも比較不可（無効）**。測定環境が修正前のビルドだった（エージェントの eBPF ファイル監視・
> ネットワーク監視がいずれも欠損、サーバはマイグレーション352以降が未適用）。
> **有効なベースラインは §12.1 を参照**。詳細＝
> [live-20260726-detection-rate-scorecard.md §2h/§2i](results/live-20260726-detection-rate-scorecard.md)。

| KPI | 無効（n=4） | 無効（2026-08-03 前半） |
|---|---|---|
| 可視性率 (rank>=Telemetry) | **100%** | **100%** (22/22) |
| 検知率 (Tactic+Technique) | **76–82%** | **100%** (22/22) ※下記注意 |
| 解析検知 (Technique のみ) | **66–73%** | **81.8%** (18/22) |
| MTTD (中央値) | 1–2秒 | **1秒** |
| MISS | 4–5件 | **0件** |

**対外指標には Technique の数字（81.8%）を使うこと。** 検知率100%のうち Tactic 判定4件は、
採点窓(120秒)がテクニック間隔(90秒)より長いために**隣接テクニックのアラートを `shareTactic()` が
拾ったもの**を含む（T1070.004←T1222.002、T1548.003←T1574.006 など）。
Tactic 判定は「その技術を検知した」証拠にならない。詳細＝
[live-20260726-detection-rate-scorecard.md §2g](results/live-20260726-detection-rate-scorecard.md)。

是正内容は (a) T1518.001/T1018 の分類器追加、(b) 探索バーストの credited-set 化、
(c) 探索群のペース分離（`DISCOVERY_PACE`）、(d) T1140/T1027 の実行順入れ替え の4点。

**単一の数値ではなくレンジで報告すること**。振れの原因は探索系が相関検知に依存し、90秒間隔では窓に閾値ぶんの
技術が揃うかがタイミング次第になるため（§9 参照）。**実ギャップとして残るのは T1548.003（正常な sudo ＝
意図的な非検知）の1件のみ**。当初あわせて計上していた T1140 は、実機の DB を確認した結果
**製品は毎回検知しており、測定側が見落としていた**ことが判明した（実行順＋アラート重複排除。
詳細＝[live-20260726-detection-rate-scorecard.md §2e](results/live-20260726-detection-rate-scorecard.md)）。

> **測定ペースはシナリオ化済み**: 上記の振れを構造的に解消するため、`run-atomics.sh` はテクニックごとに
> pace を持つ（`burst` ＝探索群を `DISCOVERY_PACE` 秒で密に、`-` ＝単発ルール検知系を `SETTLE_SECONDS` 秒で疎に）。
> 推奨実行: `SETTLE_SECONDS=90 DISCOVERY_PACE=15 ./run-atomics.sh out.csv`

> ⚠ **同じルールを踏むテクニックを近接して並べないこと**。アラートは agent+ルール名で5分間
> 重複排除される（`alert_pipeline.go`）。T1027 と T1140 はどちらも `base64 -d` を含むため同一ルールを
> 踏み、後に走る方が自分の採点窓で必ず無音になっていた。測定シナリオを組むときの必須チェック項目。

## 12.1 有効なベースライン（2026-08-03, 環境検証済み）

上記はすべて無効。**配備状態を検証したうえで測定した唯一有効な数値がこれ。**

| KPI | 環境是正直後 | バースト再発火の修正後 | **main マージ後構成（最新・確定）** |
|---|---|---|---|
| 可視性率 | 100% (22/22) | 100% (22/22) | **100%** (22/22) |
| 検知率 (Tactic+Technique) | 100% (22/22) | 100% (22/22) | **95.5%** (21/22) ※戦術共有の水増しを含む。対外指標にしない |
| **解析検知 (Technique)** | 63.6% (14/22) | 86.4% (19/22) | **86.4%** (19/22) ← 対外指標 |
| MTTD (中央値) | 7秒 | 1秒 | **1秒** |
| MISS | 0件 | 0件 | **1件**（T1059.004） |

最新列は SigmaHQ 2019件取込・新規検知器7種・eBPFファイル監視（プロセス帰属付き）を含むマージ後構成。
86.4% と残り3件の内訳（T1059.004 / T1070.004 / T1548.003）は前列と一致しており、数値は再現している。
経緯＝[live-20260726-detection-rate-scorecard.md §2k](results/live-20260726-detection-rate-scorecard.md)。

> ⚠ **この測定は当初 13.6% と出た。** 原因は製品ではなく一覧APIで、`agent_id` が NULL のアラート1件で
> `rows.Scan` が落ち、pgx が結果セットを閉じたため、それより古い38件が API から消えていた
> （`total: 56` と応答しながら 18件だけ返す）。**測定値が崩落したとき、まず製品の欠陥と解釈しないこと。**
> 計測経路（採点ツール → API → ストア）は製品と同じだけ壊れる。DB の実数と API の返却数を
> 突き合わせる1クエリで確定する。詳細＝同 §2j。

63.6% → 86.4% の差は、探索バーストの再発火がアラート重複排除に捨てられていた欠陥の是正による
（`RuleMatch.DedupKey`）。探索系5件（T1057 / T1016 / T1018 / T1049 / T1007）が Technique に上がった。
**残り3件（T1059.004 / T1070.004 / T1548.003）はいずれも良性動作そのもの**で、拾いにいくと誤検知が
増えるだけなので着手しない。現行のテストセットに対しては実質的な上限。

**T1046 が初めて Technique 判定**（`[HEURISTIC] ポートスキャン検知`）。eBPF の `tcp_connect` kprobe →
閉ポート接続の捕捉 → スキャン検知器の発火、という経路が端から端まで通った。`/proc/net` ポーリングでは
原理的に到達できなかった検知である。

### 測定前の必須チェック（これを満たさない測定は数値の意味がない）

1. **エージェント**: `go version -m <binary>` の `vcs.revision` が必要な修正コミットを含むか
   （`-tags` の有無は証拠にならない。その機能がそのリビジョンにあるとは限らない）
2. **eBPF attach**: `bpftool link show` に `sys_enter_openat` / `sys_exit_openat` / `vfs_unlink` /
   `vfs_rename` / `tcp_connect` が並ぶか
3. **自己申告**: `SELECT telemetry_mode FROM agents` が `ebpf` か（`poll` なら測らない）
4. **サーバ**: `curl -s localhost:8080/api/v1/status | jq '{version, commit, build_date, migrations}'`
   で、ビルド識別子と**適用済みマイグレーション件数・最新ファイル**を確認する。
   API が `Restarting` でないことも見る（マイグレーション失敗は再起動ループになる）。

   > ⚠ **`/api/v1/status` の `applied` を `ls server/migrations/*.sql | wc -l` と突き合わせてはいけない。**
   > `schema_migrations` は適用したファイル名を記録し続けるので、過去にリネーム・削除された
   > マイグレーションの行が残る。正常な環境でも件数は一致しない（2026-08-03 の実測で
   > `applied=440` に対しリポジトリは 427 本、差の13本はすべて過去の削除・改名分だった）。
   > 見るべきは「リポジトリにあるのに未適用のものが無いこと」であって、件数の一致ではない。
   >
   > 判定は API 起動ログの1行で足りる。`total` がリポジトリのファイル数と一致していればよい:
   > ```
   > INFO マイグレーション完了 applied=9 total=427   ← total がファイル数と一致 = 未適用ゼロ
   > ```
   > ログが流れてしまった場合は集合差を取る:
   > ```bash
   > docker exec -i kizashi-postgres psql -U edr -d edrplatform -At \
   >   -c "SELECT version FROM schema_migrations ORDER BY version" | sort > ~/db_migs.txt
   > ls server/migrations/*.sql | xargs -n1 basename | sort > ~/repo_migs.txt
   > comm -23 ~/repo_migs.txt ~/db_migs.txt   # 空であること。出力があればその分が未適用
   > ```
   > （`/tmp` は書けないホストがあるのでホームに置く。）

   > ⚠ `commit` を意味のある値にするには、ビルド時に build arg を渡すこと。compose の既定は `unknown`:
   > ```bash
   > GIT_COMMIT=$(git rev-parse --short HEAD) docker compose build api
   > ```
   > 渡し忘れても `migrations` は DB 由来なので信頼できる。**バージョン文字列より適用件数を見ること。**
5. **静置**: 測定開始前に **35分間どのテクニックも実行しない**（下記）

### ⚠ 静置35分が必要な理由

探索バースト検知器は `discCreditTTL = 30分` で「報告済みの技術を30分間は再報告しない」。測定直前に
手動でテストコマンドを叩くと、その技術が報告済みのまま測定に入り、探索群がまるごと無得点になる。

**同一ビルド・同一条件で 27.3% → 63.6% と36ポイント動いた**（静置なし / 静置35分後）。
製品の性質であって欠陥ではないが、静置を挟まない測定は数値が実力を表さない。

> **抜け道: サーバを再起動したなら静置は不要。** クレジットは検知エンジンのメモリ上の状態なので、
> `docker compose up -d api detection` で作り直せばその時点でクリアされる。2026-08-03 の確定測定は
> 静置ゼロ（再起動の91分後に開始）で探索群11件すべてが Technique 判定になっており、これを実証している。
> サーバを再ビルドしてから測る運用では、35分の待ちを別途取る必要はない。
> 逆に**サーバに触れずに測り直すときは静置が必須**。

### この測定が摘出した潜在欠陥（いずれも単体テスト・合成注入では露見しない）

1. **T1046 が実テレメトリで永久に検知不能だった** — eBPF ネットワーク監視が使いもしない `prevention`
   ビルドタグの陰にあり、`-tags ebpf` ビルドは黙って `/proc/net` ポーリングに退化。ポーリングは ESTABLISHED
   しか観測できず、**閉じたポートへの接続＝スキャンの本体が丸ごと不可視**。加えて NetworkEvent に ID が無く、
   同一秒の21接続が JetStream 重複排除で1件に潰れて閾値(15ポート)に到達できなかった。
2. **探索バーストが「個数が増えたときだけ再発火」** — 間隔を空けた偵察では窓内の技術が入れ替わるだけで
   個数が増えず、発火後に列挙された技術が永久に無報告。報告済み集合を持つ方式へ是正。
3. **T1518.001 / T1018 の分類パターンが皆無** — EDR を探す `ps aux | grep falcon` は「ただのプロセス一覧」、
   `/etc/hosts` 読みは分類なしで、キルチェーンにもバーストにも寄与していなかった。
4. **ランサム検知が systemd を誤検知**（60ファイル/30秒で sev9）— OS/サービス所有ツリーを burst カウントから
   除外して是正。プロセス許可リストではなく**パス基準**（`systemd` を名乗るドロッパーで回避されないため）。

詳細と実機ログ＝[results/live-20260726-detection-rate-scorecard.md](results/live-20260726-detection-rate-scorecard.md)。

### 教訓

- **Tier 3 を外した測定は営業資料に使えない**。第1回・第2回の 100% は得意領域のみの数字だった。
- **測定条件が数値を支配する**。同一ビルドで 76%→95%→100% と動いた（窓の相互汚染・UEBA の無差別加点・
  バックログ遅延）。条件を書かないスコアは無意味。
- **実機測定は「検知率を知る」ためだけでなく「センサーが本当に届いているか」を暴くために回す**。今回の
  4欠陥はいずれもコードとしては正しく、テレメトリの到達性・帰属・重複排除という配管側の問題だった。
