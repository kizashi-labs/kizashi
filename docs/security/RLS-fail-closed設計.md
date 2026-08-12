# RLS エスケープ節 fail-closed 化 — フェーズ分割設計

> **状態**: 設計のみ(未実装)。本体は大規模改修のため専用フェーズで実施する。
> **前提**: [マルチテナント分離ハードニング.md](マルチテナント分離ハードニング.md) の手順1/2 + migration 324-328 が適用済みであること。
> **重大度**: 中(残余リスクの解消。手順1/2 と多層防御で主要な BOLA は既に緩和済み)。

---

## 1. 目的と残余リスク

現行 RLS ポリシー(agents/alerts/incidents/users)は fail-**open**:

```sql
USING (tenant_id::text = current_setting('app.tenant_id', TRUE)
       OR current_setting('app.tenant_id', TRUE) IS NULL
       OR current_setting('app.tenant_id', TRUE) = '')
```

エスケープ節(`IS NULL OR = ''`)により、**`app.tenant_id` を設定し損ねた接続は全テナントにアクセスできる**。API リクエストで tenant 設定が漏れるバグ(例: JWT に tenant_id 欠落、middleware 適用漏れの新規ルート)が即クロステナント漏洩になる。理想は API 接続を fail-**closed**(`USING (tenant_id = current_setting(...)::uuid)`、未設定なら 0 行)にすること。

## 2. なぜ単純にエスケープ節を外せないか(2026-07 監査結論)

`app.tenant_id` をセットするのは HTTP リクエスト経路(`tenantMiddleware`)のみ。以下は**同一 `edr_app` プールを `app.tenant_id` 未設定で共有し、エスケープ節に依存**している:

- **cmd/api 内の約35本のバックグラウンドワーカ**: HeartbeatMonitor / DeadAgentCleanup / DataRetentionCleaner(DELETE alerts) / 各種アラート生成 detector・correlator(IOCMatcher, RealtimeCorrelator, VulnerabilityScanner, NetworkAnomalyDetector, InsiderThreatDetector 等) / 集計 collector(SecurityMetrics, SecurityKPI, Compliance) / IncidentEscalator / AlertAggregator / 通知系(DigestScheduler, AlertDigestSender, LicenseExpiryNotifier, BillingGraceNotifier) / in-process 検知パイプライン ほか。
- **認証前 HTTP 経路**: ログイン(`users`)、agent heartbeat(`agents`/`alerts`)、enrollment(`agents`)、Wazuh/Mobile/Log ingest(`agents`/`alerts`)、scan-results。

単純にエスケープ節を削除すると、これらが 0 行/INSERT 拒否になり **ログイン全滅・agent 永久オフライン・アラート生成/保持削除/集計/通知の全停止**を招く。

## 3. フェーズ分割設計

### Phase 0: 前提整備(一部 #541 で実施済み)
- [x] alerts/incidents に tenant_id DEFAULT(migration 328)。
- [ ] **alert/incident 生成経路での agent→tenant 解決**: 現状 INSERT は tenant_id 未設定(DEFAULT で既定テナント)。マルチテナントでは対象 agent のテナントを解決して明示設定する必要がある。約15本の生成ワーカ + ingest 経路が対象。これが最も工数の大きい下地。

### Phase 1: worker ロールの導入
- migration: 非スーパーユーザ `edr_worker` ロールを作成(edr_app と同様 NOLOGIN・パスワード未設定で用意、GRANT は edr_app と同一)。
- RLS ポリシーを**ロール別**にする:
  - `edr_worker` 向け permissive ポリシー: `USING (true)`(全テナント可視)。
  - 既存の tenant ポリシーは据え置き(全ロール対象)。この時点では挙動不変。

### Phase 2: 別プロセスを worker ロールへ
- cmd/ingestion / cmd/detection の `APP_DATABASE_URL` を `edr_worker` の DSN に向ける(env のみ)。cmd/updater は RLS テーブル不使用のため任意。
- これらは別プロセスなので配線変更不要。エスケープ節無しでも全テナント処理が維持される。

### Phase 3: cmd/api の第2プール
- cmd/api に**2本目のプール**(`WORKER_DATABASE_URL` = edr_worker)を追加。
- **バックグラウンドワーカ + 認証前ハンドラ**(ログイン/heartbeat/enrollment/ingest)をこの worker プールに配線し直す。認証済みハンドラは従来の edr_app プール(tenant scoped)のまま。
  - 配線点: `cmd/api/main.go` の各ワーカ生成(`db.Pool()` を渡している箇所 約35本)と、public ルートのハンドラが使う store。
- ★これが最大の変更。ワーカ/ハンドラごとにどちらのプールを使うべきかを棚卸しし、テストで担保する。

### Phase 4: API ポリシーを fail-closed 化
- 全 Phase 完了後、tenant ポリシーからエスケープ節を除去:
  ```sql
  USING (tenant_id::text = current_setting('app.tenant_id', TRUE))
  ```
- `edr_worker` は Phase 1 の `USING (true)` ポリシーで全テナント可視のまま。`edr_app`(認証済み API)は自テナントのみ = fail-closed。
- WITH CHECK も明示(INSERT/UPDATE で他テナント行を作らせない)。

### Phase 5: 検証・ロールアウト
- ステージングで: ログイン/heartbeat/enrollment/ingest/各ワーカ/認証済み API の全経路を回帰。
- app.tenant_id を設定し損ねた API リクエストが**0 行(403/404 相当)**になることを確認(fail-closed の実証)。
- ロールバック: ポリシーをエスケープ節付きに戻す migration + `WORKER_DATABASE_URL` 未設定でフォールバック。

## 4. リスクと非対象

- 各 Phase は前 Phase まで挙動不変(env フォールバック/ポリシー据え置き)を保つよう設計する。Phase 4 のみが挙動を変える。
- 単一テナント運用では fail-closed 化の実益は小さい(全データが既定テナント)。マルチテナント本番投入前に完了させるのが目標。
- 本設計は残余リスクの解消であり、主要な BOLA は手順1/2(FORCE RLS + edr_app)+ 対応アクションのアプリ層検証で既に緩和済み。
