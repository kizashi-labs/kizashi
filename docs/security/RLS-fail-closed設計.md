# RLS エスケープ節 fail-closed 化 — フェーズ分割設計

> **状態**: **下ごしらえまで実装済み。** 方式はロール分割から「名乗り」に
> 変えた（下の「7. 方式の変更」）。残るのは公開経路 6 件の判定だけ。
> **前提**: [マルチテナント分離ハードニング.md](マルチテナント分離ハードニング.md) の手順1/2 + migration 324-328 が適用済みであること。
> **重大度**: 中(残余リスクの解消。手順1/2 と多層防御で主要な BOLA は既に緩和済み)。

---

## 7. 方式の変更 — ロール分割ではなく「名乗り」(migration 450)

**下の 3 章〜6 章はロール分割 (`edr_worker`) の設計です。測った結果、
この配備では効かないことが分かったので採りませんでした。**

- 既定の配備は **DSN が 1 本**です（`APP_DATABASE_URL` は未設定で
  `DATABASE_URL` にフォールバック。このリポジトリの docs 自身が
  「未実施だとテナント分離は無効のまま」と書いています）。
  4 表は **FORCE RLS** なので所有者 `edr` も方針の対象ですが、
  **API と系が同じロールで繋ぐ配備では、ロール別方針は両者を
  区別できません。**
- CI の Postgres も所有者 `edr` の 1 本です。つまり
  **ロール案は CI で一度も実行されません。**

採った形は、方針の中で「全テナントを見る」と**名乗らせる**ものです:

```sql
-- いま (migration 450): 名乗りの項を足しただけ。挙動は変わっていない
USING (tenant_id::text = current_setting('app.tenant_id', TRUE)
       OR current_setting('app.tenant_id', TRUE) = 'system'
       OR current_setting('app.tenant_id', TRUE) IS NULL   -- ← 落とす
       OR current_setting('app.tenant_id', TRUE) = '')     -- ← 落とす
```

配線の手間はロール案と同じで、違うのは**配備側に何を要求するか**です。
名乗りは新しいロールも 2 本目の DSN も要らず、いまの 1 本 DSN の配備で
そのまま効き、CI でも実行されます。ロール分割と併用もできます
（多層防御としては上乗せになります）。

### 実装済み

| 何を | どこに |
| --- | --- |
| 名乗りの仕組み | `store.WithSystemAccess` / `store.SystemTenant` |
| 外から `system` を名乗れないこと | `store.prepareConnForTenant`（JWT の tenant_id はここに来ます） |
| 方針への項の追加 | migration 450（**挙動は変わりません**） |
| 背景ワーカ 33 本 | `cmd/{api,ingestion,detection}` の**プロセス ctx 1 か所ずつ**。設計書が「約35本の配線」と見積もっていた部分は、ctx が 1 本なので 3 か所で覆えました |
| 認証前の HTTP 経路 16 件 | `mw.SystemAccessMiddleware()` を group / 経路ごとに |
| 台帳 | `internal/api/system_access_ledger_test.go` |

`cmd/api` のプロセス ctx を包んでも HTTP 要求には伝わりません ——
gin は `http.ListenAndServe` を `BaseContext` 無しで呼ぶので、
要求ごとの ctx は `context.Background()` から生えます。

### 残っているのは 1 つだけ

公開経路のうち **6 件が、4 表に触るかどうか未判定**です
(`undecidedPublicRoutes`)。落とすと、触っていた場合に 0 行で静かに
壊れます。**この一覧が空になったら、エスケープ節を落とせます。**

判定できていない理由は、gin の group 変数が関数をまたいで同じ名前で
使われていて（`dw` が 2 か所、`v1` / `taxii` も）、素朴な走査が誤判定
するためです。1 件ずつハンドラを読む必要があります。

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
