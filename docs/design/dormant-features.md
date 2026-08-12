# 休眠機能の設計提案 (Dormant Features)

カバレッジ調査およびスキーマ不整合バグ修正(#520 / #522 / #530)の過程で、
「コードは存在するが、バッキングとなるテーブル/カラム/データ経路が無いために
実質無効化されている機能」が複数見つかった。本ドキュメントはそれらを実機能化
するための設計提案である。

各項目は **A: すぐ実装可能(サーバー内で完結)** と **B: エージェント+プロトコル
拡張が必要(段階実装)** に分類する。

---

## 分類サマリ

| # | 機能 | 現状 | 分類 | 概算工数 |
|---|------|------|------|----------|
| 1 | エージェント CPU/メモリ健全性アラート | ✅ 実装済み #534 | **A** | 小(0.5〜1日) |
| 2 | ソフトウェアインベントリ → 脆弱性スキャン | ✅ 実装済み #583 | **B** | (実際は小・テーブル名修正) |
| 3 | 資産重要度スコア (asset_criticality_scores) | ✅ 実装済み #572 | **B'**(サーバー内で自己算出可) | 中(1〜2日) |
| 4 | エンドポイント暗号化状態 (endpoint_encryption) | ✅ 実装済み | **B** | 中 |
| 5 | ハードニングベースライン (endpoint_hardening_baselines) | ✅ 実装済み | **B** | 中（内蔵チェックで実現） |

---

## 1. エージェント CPU/メモリ健全性アラート 【A: ✅ 実装済み #534】

> **ステータス: 実装済み(#534)。** 以下の設計どおりサーバー側のみで実装。
> migration 324 で `agents.cpu_usage`/`memory_usage_mb`/`metrics_updated_at` を追加、
> `AgentStore.UpdateMetrics` を Heartbeat から呼び出して保存、`checkCPUMemory` を
> 新列参照(メモリは MB→`total_memory_mb` 比%換算)へ修正。高負荷エージェントが
> 検出されることをテストで固定済み。


### 現状
- `scheduler/agent_health_alerter.go` の `checkCPUMemory` が
  `agents.settings->>'cpu_usage'` を読むが、`agents` に `settings` 列は存在しない
  → 常に空 → 高負荷アラートが一切発火しない(静かに握りつぶし)。
- 一方 **`HeartbeatRequest` は既に `cpu_usage`(field5)/`memory_usage_mb`(field6)
  を送信済み**。`ingestion` の `Heartbeat` ハンドラは `UpdateLastSeen(...)` を呼ぶが、
  この2値を渡しておらず、サーバーが受信データを捨てている。

### 設計(サーバー内で完結・エージェント変更不要)
1. **マイグレーション**: `agents` に列追加
   ```sql
   ALTER TABLE agents ADD COLUMN IF NOT EXISTS cpu_usage           DOUBLE PRECISION;
   ALTER TABLE agents ADD COLUMN IF NOT EXISTS memory_usage_mb     DOUBLE PRECISION;
   ALTER TABLE agents ADD COLUMN IF NOT EXISTS metrics_updated_at  TIMESTAMPTZ;
   ```
2. **保存経路**: `AgentStore` に `UpdateMetrics(ctx, agentID, cpu, memMB)` を追加、
   `Heartbeat` ハンドラから `req.GetCpuUsage()`/`req.GetMemoryUsageMb()` を渡す
   (または `UpdateLastSeen` を拡張)。
3. **アラート側**: `checkCPUMemory` のクエリを
   `settings->>'cpu_usage'` → `cpu_usage` / `memory_usage_mb` 列参照に修正。
   - **単位の整合**: メモリは MB 絶対値で届く。現行の `memThreshold`(%想定)は
     意味を成さないので、(a) `total_memory_mb` 列がある(確認済み)ので
     `memory_usage_mb / total_memory_mb * 100` を % 化してしきい値比較、
     が最も自然。CPU は 0–100(%) 前提でそのまま比較。

### 効果
- 死んでいたフリート健全性アラートが実際に機能。
- カバレッジも増(Heartbeat の metrics 経路 + alerter の実行経路)。

**推奨: これは即実装すべき。** 他項目と独立した1PRで完結できる。

---

## 2. ソフトウェアインベントリ → 脆弱性スキャン 【B: ✅ 実装済み #583】

> **ステータス: 実装済み(#583)。** 調査の結果、収集経路(エージェントの
> `internal/software` による rpm/dpkg/Windows レジストリ収集 → `POST
> /api/v1/agents/:id/software/report` → `endpoint_software` テーブル保存)は
> **既に全て存在**していた。唯一の断線は最終段で、`vulnerability_scanner.go` と
> `scorer.go` が存在しないテーブル名 `software_inventory` を参照していた点。
> 両者を実在する `endpoint_software` に向け直し、脆弱性スキャン(NVD/CVE 突合)と
> NIST-CSF ID.AM-2 が実データで動作するようにした。以下は当初の(過大見積り)設計。

### 現状
- `scheduler/vulnerability_scanner.go` が
  `SELECT id, agent_id, name, version FROM software_inventory` を読むが、
  個別ソフト行を保持するテーブルが存在しない
  (移行082が作るのは集計用 `software_inventory_snapshots` のみで name/version 無し)。
- `scorecard/scorer.go:148` も `COUNT(*) FROM software_inventory` を参照。

### 設計
1. **マイグレーション**: 実体テーブルを新設
   ```sql
   CREATE TABLE software_inventory (
     id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
     agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
     name TEXT NOT NULL,
     version TEXT NOT NULL,
     publisher TEXT,
     install_date DATE,
     first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
     last_seen  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
     UNIQUE(agent_id, name, version)
   );
   ```
2. **収集経路(要エージェント作業)**: 現行 agent proto には software-inventory
   イベントが無い。`agent/v1` に `SoftwareInventoryEvent`(name/version/publisher の
   繰り返し)を追加 → proto 再生成 → エージェント側でOS別収集
   (Windows: レジストリ Uninstall / WMI、Linux: dpkg/rpm、macOS: system_profiler)
   → ingestion に upsert ハンドラ追加。
3. **サーバー側配線**: ingestion に inventory 受信 → `software_inventory` upsert。
   既存の `software_inventory_snapshots`(日次集計)もこの実体から派生生成に統一。

### 工数/リスク
- エージェント3OS分の収集実装 + proto 変更 + サーバー受信で **大**。
- 脆弱性スキャナ(NVD突合)は実装済みなので、インベントリさえ入れば即機能する。

---

## 3. 資産重要度スコア (asset_criticality_scores) 【B': ✅ 実装済み #572】

> **ステータス: 実装済み(#572)。** 設計どおりサーバー内で自己算出。migration 325 で
> `asset_criticality_scores` を新設し、`AssetCriticalityScorer` スケジューラが
> タグ + 未解決重大アラート + 重大/高脆弱性からエージェント単位の 0-100 スコアを
> 定期算出。scorer の ID.AM-5 が実データ化。

### 現状
- `scorecard/scorer.go:160` が `COUNT(*) FROM asset_criticality_scores` を
  「証跡あり=加点」に使うのみ。テーブル不在で常に0点。

### 設計(エージェント不要・サーバー内算出が可能)
資産重要度はサーバーが既に持つデータ(エージェントのタグ、露出、アラート/脆弱性
密度)から**導出**できる。専用スケジューラで定期算出:
```sql
CREATE TABLE asset_criticality_scores (
  agent_id UUID PRIMARY KEY REFERENCES agents(id) ON DELETE CASCADE,
  score INT NOT NULL,               -- 0-100
  factors JSONB NOT NULL DEFAULT '{}',
  calculated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```
- 算出ロジック(例): タグ(`server`/`domain_controller` 等の重み)+ 未解決重大
  アラート数 + 重大脆弱性数 + 外部露出。既存の RiskScores ロジック(#522修正済)を
  流用可能。
- 新スケジューラ worker + ハンドラ(一覧/詳細)。

### 工数/リスク
- **中**。純サーバー実装で、コンプライアンススコアも実データ化する。
- 重み付けは製品判断が要る(初期値は提案可能)。

---

## 4. エンドポイント暗号化状態 (endpoint_encryption) 【B: ✅ 実装済み】

> **ステータス: 実装済み。** #2 のソフトウェアレポーターと同じ HTTP パターンで実装
> (proto 拡張は不要)。以下の設計どおり:
> - migration 362 で `endpoint_encryption` を新設(agent_id PK / encrypted / method /
>   details / reported_at)。
> - エージェント新パッケージ `internal/encryption` が OS 別に暗号化状態を探査
>   (Linux: `lsblk` で dm-crypt/LUKS 検出、Windows: `manage-bde`、macOS:
>   `fdesetup status`)し、`POST /api/v1/agents/:id/encryption/report` へ 12 時間毎に送信。
> - サーバーは agent_id 単位で upsert。scorer の PR.DS-1(データ保護)が実データ化。

### 現状(実装前)
- `scorer.go:266` が `COUNT(*) FROM endpoint_encryption` を参照。テーブル不在。

### 設計
- **マイグレーション**:
  ```sql
  CREATE TABLE endpoint_encryption (
    agent_id UUID PRIMARY KEY REFERENCES agents(id) ON DELETE CASCADE,
    encrypted BOOLEAN NOT NULL,
    method TEXT,                     -- bitlocker / filevault / luks
    details TEXT,
    reported_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );
  ```
- **収集(エージェント)**: 専用レポーターが暗号化状態を報告
  (Windows: `manage-bde`、macOS: `fdesetup status`、Linux: `lsblk`)。
- サーバー側 upsert(agent-facing 公開エンドポイント)。

### 工数/リスク: **中**(proto 拡張不要・HTTP レポーターで完結)。

---

## 5. ハードニングベースライン (endpoint_hardening_baselines) 【B: ✅ 実装済み】

> **ステータス: 実装済み。** #2/#4 と同じ HTTP レポーターパターンで実装（proto 拡張不要）。
> OpenSCAP 等の外部依存は導入せず、エージェント内蔵の軽量 CIS 風チェックで実現:
> - migration 363 で `endpoint_hardening_baselines`（agent×benchmark のロールアップ）と
>   `endpoint_hardening_assessments`（チェック単位の passed 行）を新設。
> - エージェント新パッケージ `internal/hardening` が OS 別に設定監査を実行し
>   `POST /api/v1/agents/:id/hardening/report` へ 24 時間毎に送信:
>   - Linux: sshd_config(PermitRootLogin/PasswordAuthentication)、PASS_MAX_DAYS、
>     cron.allow、/tmp sticky bit、コアダンプ制限（ファイル読取ベースで堅牢）
>   - macOS: FileVault/Gatekeeper/SIP（`fdesetup`/`spctl`/`csrutil`）
>   - Windows: ファイアウォール/BitLocker（`netsh`/`manage-bde`）
> - サーバーはトランザクションで baseline upsert + assessment 総入れ替え。
>   scorer の PR.IP-1 が合格率で実データ化。
>
> **可視化の断線修正（後続）:** 調査の結果、ハードニングは2系統とも休眠していた。
> 171 の `hardening_baselines`/`hardening_assessments`（管理UI + 読み取りハンドラは
> 既存だが populate 経路が皆無）と、363 の `endpoint_hardening_*`（agent/scorer 用だが
> UI なし）。エージェントの収集データ（benchmark + 各チェック合否）は 171 の豊富な
> スキーマ（baseline=ポリシー+checks JSONB、assessment=agent単位スコア+findings JSONB）
> に綺麗に一致するため **171 系に一本化**した（migration 364）: 報告エンドポイントと
> scorer を `hardening_*` に向け直し、既存の管理UIをそのまま実データ化、冗長な 363 系
> テーブルをドロップ。暗号化側も `encryption_mgmt_handler` のモックを実 `endpoint_encryption`
> クエリへ置換し、管理UIが実データ表示に。

### 現状(実装前)
- `scorer.go:279` が `COUNT(*) FROM endpoint_hardening_baselines` を参照。テーブル不在。

### 設計
- CIS Benchmark 等の設定監査結果を保持:
  ```sql
  CREATE TABLE endpoint_hardening_baselines (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    benchmark TEXT NOT NULL,         -- e.g. "CIS Ubuntu 22.04 v1.0"
    passed INT NOT NULL,
    failed INT NOT NULL,
    total  INT NOT NULL,
    details JSONB,
    scanned_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );
  ```
- **収集(要エージェント)**: CIS チェックをエージェントで実行(最も重い)、
  または OpenSCAP 等の外部ツール連携。proto 拡張 + サーバー受信。

### 工数/リスク: **大**(ベンチマーク実装が本体)。

---

## 推奨ロードマップ

1. **#1 CPU/メモリ健全性アラート** — ✅ **実装済み(#534)**。
2. **#3 資産重要度スコア** — ✅ **実装済み(#572)**。純サーバー算出でコンプライアンス実データ化。
3. **#2 ソフトウェアインベントリ** — ✅ **実装済み(#583)**。収集経路は既存で、テーブル名の断線を修正するのみだった。
4. **#4 暗号化状態** — ✅ **実装済み**。proto 拡張不要の HTTP レポーターで収集。
5. **#5 ハードニング** — ✅ **実装済み**。エージェント内蔵の軽量 CIS 風チェックで収集。

いずれも「テーブルを空で作るだけ」では COUNT が0のままで無意味であり、
**データ収集/算出経路とセットで初めて機能する**点に注意。**休眠機能5件はすべて実機能化完了。**

## 後続：収集データの活用

- **可視化**：管理UI（endpoint-hardening / encryption-mgmt）を実データに接続（171系一本化 + モック撤去）。
- **検知・自動対応**：`ComplianceAlerter` スケジューラを追加。収集した暗号化/ハードニング
  ポスチャを走査し、ディスク暗号化が無効なエンドポイント、ハードニング合格率が閾値
  （60%）未満のエンドポイントを検知して `alerts`（severity=medium, source=compliance_posture）
  を自動生成。24時間デデュープでスパムを防止。スコアカードの数値だけでなく実アラートとして
  SOC のキューに乗るようにした。
- **ソフト脆弱性の可視化断線修正**：脆弱性スキャナ（#583）は実結果を `vulnerabilities` に
  書き込むが、UI ハンドラ（`SoftwareVulnerabilityHandler.List`）は書き込み経路の無い
  `vulnerability_findings` を読み、空なら endpoint_software のヒューリスティックにフォールバック
  していたため、実スキャナ結果（本物の CVE）が UI に出ていなかった。List に `vulnerabilities`
  を読む中間段を追加し、実スキャナ結果を優先表示するよう修正。
