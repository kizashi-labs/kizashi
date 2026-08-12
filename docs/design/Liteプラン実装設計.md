# Lite プラン 実装設計書

> **ステータス（2026-04-24 更新）:** 🟢 **Phase 0–7 全て実装完了**、v1.3.3 で本番反映済。残作業は EnforceAgentLimit integration test と OpenAPI 402 schema enum 化（低優先・後日）。
> **対象読者:** 開発チーム / プロダクトマネージャー / 営業
> **最終更新日:** 2026年4月24日
> **関連:** [`docs/sales/pricing-plan-smb-revised.md`](../sales/pricing-plan-smb-revised.md)（プラン提案・Lite 部分のみ承認・実装済）

---

## 🟢 実装完了サマリー（2026-04-24）

| Phase | 内容 | リリース | 主要 commit |
|---|---|---|---|
| 0 | MDM gate (Free 除外) | v1.1.5 | `d842458` |
| 1 | License 定数 (`PlanLite` + features + limits) | v1.2.0 | `9c70f10` |
| 2 | Billing handler (Stripe Lite Price + MRR) | v1.2.0 | `9c70f10` |
| 3 | Frontend (Plan.Lite + バッジ + プラン比較表) | v1.2.0 | `3f61e43`, `ae71327` |
| 4 | Stripe Dashboard 設定（Test mode 検証完了） | — | ユーザー作業 |
| 5 | Signup UI (4 ボタン化 + 5 EP step + 比較マトリクス) | v1.3.0, v1.3.1 | `4af97b1`, `1fccc6a` |
| 6 | Lite E2E middleware tests + MDM `required_plan` fix | v1.3.3 | `1c1d8c7` |
| 7 | docs (pricing.md / OpenAPI / 営業資料) | v1.3.0, doc-only | `4af97b1`, `66d73ff` |

**派生バグ修正**:
- v1.2.1: Auto-update credential plumbing (PAT 二重管理を `.env` 単一更新に統一)
- v1.3.2: Lite `agent_limit` を Stripe quantity から導出（顧客が買った EP 数 ≠ tier max への対応）
- v1.3.3: `required_plan(MDM)` を `Enterprise` → `Starter` に修正（API contract）

**本番運用ステータス**:
- EC2 検証環境で v1.3.3 まで auto-update により反映完了
- Stripe Test mode で Lite signup → Checkout → webhook → license_info 同期 end-to-end 確認済
- DB 例: `plan=lite, agent_limit=10, user_limit=3, features={basic_detection,alerts,reports}`

**残作業（低優先・後日）**:
- ⏳ `EnforceAgentLimit` integration test — `Manager.GetUsage` が DB 依存のため `//go:build integration` 必要
- ⏳ `docs/openapi.yaml` の 402 response schema で `required_plan` を enum 固定化
- ⏳ 営業チームによる `docs/sales/competitive-battlecards.md` Section 5 + `docs/sales/roi-calculator.md` シナリオ 0 のレビュー（数値検証）

---

## 1. 設計の前提

- 営業提案 `pricing-plan-smb-revised.md` の Lite プラン（5〜45 EP, ¥500/EP/月, 5 台刻み）を実装するための差分設計
- **新機能の追加は不要** — 既存の `RequireFeature` / `EnforceAgentLimit` ミドルウェアが Lite の機能制限を自動的に enforce する
- 主な作業は **plan 定数の追加** + **Stripe Product / Price 作成** + **UI のプラン分岐**
- Free 5 EP cap、Starter 50 EP〜、Pro 200 EP〜、Enterprise 1,000 EP〜の現行階段を維持し、その間に Lite を追加

---

## 2. プラン階段（Lite 追加後）

| プラン | EP 帯 | 単価 | 最小月額 | 主機能 | 主な追加機能 vs 下位 |
|---|---|---|---|---|---|
| Free | 〜5 EP | ¥0 | ¥0 | 基本検知・アラート | （ベース） |
| **🆕 Lite** | **5〜45 EP**（5 台刻み） | **¥500/EP/月** | **¥2,500** | + レポート、メールサポート | **Reports**, ユーザー +1, 48h SLA メール |
| Starter | 50〜199 EP | ¥1,800/EP/月 | ¥90,000 | + MDM | **MDM** |
| Professional | 200〜999 EP | ¥2,800/EP/月 | ¥560,000 | + AI 調査・SIEM・Playbook・YARA・Threat Hunting | AI / SIEM / Playbook / YARA / ML / TH |
| Enterprise | 1,000+ EP | 個別見積 | 個別見積 | + Multi-tenant・Compliance・XDR・SOAR・Forensics | + 全機能 |

**Lite の意味づけ:**
- Free と Starter の間（6〜49 EP 規模）の **有償エントリー帯** を埋める
- 「Free + Reports + メールサポート + 5 台刻みで増やせる柔軟性」が差別化要素
- MDM が必要な顧客は Starter にアップセル

---

## 3. コード変更スコープ

### 3.1 `server/internal/license/manager.go`（最重要）

```go
// Plan constants に Lite を追加
const (
    PlanStarter      = "starter"
    PlanProfessional = "professional"
    PlanEnterprise   = "enterprise"
    PlanFree         = "free"
    PlanLite         = "lite"  // ← 新規
    PlanBusiness     = PlanProfessional
)

// planFeatures に Lite エントリ追加（Starter から MDM を除いたもの）
var planFeatures = map[string][]string{
    // ... existing entries ...
    PlanLite: {
        FeatureBasicDetection,
        FeatureAlerts,
        FeatureReports,
    },
}

// planAgentLimits に Lite エントリ追加
var planAgentLimits = map[string]int{
    // ... existing entries ...
    PlanLite: 45,  // ← 5 台刻みで最大 45
}

// planUserLimits に Lite エントリ追加
var planUserLimits = map[string]int{
    // ... existing entries ...
    PlanLite: 3,
}
```

**注意:** `planFeatures[PlanStarter]` は現在 `{BasicDetection, Alerts, Reports}` だが、**MDM 機能の feature key が現状未定義**。Starter の MDM を厳密に gate するなら `FeatureMDM = "mdm"` を新規追加し、`planFeatures[PlanStarter]` に含める必要がある（`PlanLite` には含めない）。MDM が現在 feature gate されていない場合、Lite でも MDM が使えてしまう。実装着手前に **MDM の現行 gate 状態を要検証**（実装チェックリスト §6 に記載）。

### 3.2 `server/internal/billing/handler.go`

```go
// PriceMap init に Lite 追加
func init() {
    if v := os.Getenv("STRIPE_PRICE_STARTER"); v != "" {
        PriceMap[v] = license.PlanStarter
    }
    if v := os.Getenv("STRIPE_PRICE_LITE"); v != "" {  // ← 新規
        PriceMap[v] = license.PlanLite
    }
    // ... existing ...
}

// planAgentLimit switch case に Lite 追加
func planAgentLimit(priceID string) int {
    plan := PriceMap[priceID]
    switch plan {
    case license.PlanLite:        // ← 新規
        return 45
    case license.PlanStarter:
        return 49
    case license.PlanProfessional:
        return 299
    case license.PlanEnterprise:
        return 0
    }
    return 49
}
```

### 3.3 環境変数 / `.env.example`

```bash
# Stripe Price IDs
STRIPE_PRICE_LITE=price_XXXXXXXXXXXXXX        # ← 新規 (¥500 × N EP × monthly, N ∈ {5,10,...,45})
STRIPE_PRICE_STARTER=price_XXXXXXXXXXXXXX
STRIPE_PRICE_BUSINESS=price_XXXXXXXXXXXXXX
STRIPE_PRICE_ENTERPRISE=price_XXXXXXXXXXXXXX
```

### 3.4 Frontend (`frontend/lib/usePlan.ts` ほか)

- `usePlan()` の戻り値型に `'lite'` を追加
- `PlanGate` コンポーネント / アップグレードプロンプトに Lite を選択肢として追加
- プラン比較テーブル UI に Lite カラム追加
- Lite バッジコンポーネント（紫色など、Starter とは別色推奨）
- ライセンス画面で Lite プラン名表示と「Starter にアップグレード」CTA

### 3.5 Stripe Dashboard 側作業（コードではない）

1. Product 作成: `Kizashi Lite`
2. Price 作成（Recurring・Monthly・Volume tier）:
   - `tier_mode: graduated` で 5 台刻み（5/10/15/20/25/30/35/40/45 各 SKU 化が複雑なら、quantity-based pricing で `unit_amount: 50000` (¥500) × `quantity` でも OK）
3. Checkout の `quantity` を 5 の倍数に制限（min=5, max=45, step=5）— Stripe Checkout の `adjustable_quantity` で実装、または signup ページ側で UI 制約
4. Customer Portal で Lite ↔ Starter のプラン変更を許可

---

## 4. テスト追加スコープ

| ファイル | テスト内容 |
|---|---|
| `server/internal/license/manager_test.go` | Lite プランの `planAgentLimits` / `planUserLimits` / `planFeatures` 期待値、`HasFeature` で AI / SIEM / MDM / Playbook が false |
| `server/internal/billing/handler_test.go` | `planAgentLimit("price_lite")` が 45 を返す、Lite Price ID → PlanLite マッピング |
| `server/internal/middleware/plan_gate_test.go` | Lite プランで `RequireFeature(FeatureAIInvestigation)` が HTTP 402 を返す |
| `frontend/lib/usePlan.test.ts` | `'lite'` plan に対する `hasFeature` の戻り値 |
| `frontend/components/PlanGate.test.tsx` | Lite plan で AI/MDM 機能の gate 動作 |

**Coverage 目標:** Lite プランに関する分岐は 100% 通過させる（既存の Starter テストパターンを踏襲）。

---

## 5. DB マイグレーション

**不要。** `license_info.plan` カラムは TEXT 型で任意の値を受け入れ可能。新規プラン追加は ENUM 型でないので migration なしで動く。

ただし、既存 Free 顧客が Lite に切り替わる経路（Stripe Checkout → webhook → license update）が正常に動くことを既存の `cancellation-grace-period` 統合テストと合わせて検証する。

---

## 6. 実装着手前のチェックリスト（pre-flight）

実装に入る前に以下を verify:

- [ ] **MDM の feature gate 状態確認** — `RequireFeature(FeatureMDM, ...)` が router/handlers のどこかで使われているか grep。使われていなければ Lite でも MDM が leakage するので、`FeatureMDM` 定数追加と handler 側の RequireFeature 適用が必要
- [ ] **Stripe Price ID の自然な単位** — `quantity-based`（¥500 × N、N=5,10,...,45）か、9 個の SKU（Lite 5EP / Lite 10EP / ... / Lite 45EP）か、決定。前者の方が運用が楽だが Stripe Customer Portal の表示が分かりにくい場合あり
- [ ] **Lite の保持期間** — 提案では「30 日」だが、Free と同じだと差別化が弱い。**60 日に拡張する**選択肢あり（DB 上の保持ポリシーは plan 別に分岐していないので、これは新規の `planRetentionDays` map 追加が必要 — 実装コスト +0.5 日）
- [ ] **Lite の signup 経路** — 自社 signup フロー（`/signup`）で Lite が選択肢として現れるか、それとも営業経由のみか。前者なら signup ページ UI 変更が +1 日
- [ ] **Lite からのアップグレード経路** — Customer Portal で Lite → Starter に切り替えた場合、`license_info.plan` 更新と `agent_limit` 拡張、grace period 不要かを Stripe webhook handler 側で検証

---

## 7. 工数見積（最小実装：5 SKU 案 / 保持期間据え置き）

| Phase | 内容 | 工数 |
|---|---|---|
| 1 | License 定数追加 + planFeatures/Limits 追加 + 単体テスト | 1 日 |
| 2 | Billing handler に Lite Price ID 分岐 + テスト | 0.5 日 |
| 3 | Frontend: usePlan / PlanGate / プラン比較 UI に Lite 追加 | 2 日 |
| 4 | Stripe Dashboard: Product / Price / Customer Portal 設定 | 0.5 日 |
| 5 | Signup フロー UI で Lite を選択可能に + 5 台刻み制約 | 1 日 |
| 6 | E2E テスト（Lite 契約 → エージェント 45 台到達 → 46 台目で 402、AI 機能で 402） | 1 日 |
| 7 | ドキュメント更新（pricing.md / OpenAPI / sales 資料公式化） | 1 日 |
| **計** | | **約 7 日** |

**追加オプション工数:**
- MDM feature gate 新規実装（+1 日）
- Lite 保持期間 60 日（plan 別保持期間 map 新設）（+0.5 日）
- バトルカード / ROI 計算 / オンボーディング資料の Lite 対応（+1 日）

---

## 8. 主な Pros / Cons

**Pros:**
- 既存アーキテクチャ（FeatureGate）に乗るため、新機能不要 = リスク小
- 工数 ~7 日で SMB 市場に参入可能
- Free → Lite → Starter の自然な階段が完成し、転換率改善が期待できる
- Stripe webhook 経由の自動プロビジョニングが既に動いているので、運用負荷が小さい

**Cons:**
- MDM が現在 feature gate されていない場合、Lite でも MDM が漏れる → 価格差別化失敗のリスク
- Stripe の 5 台刻み制約を Customer Portal 上で表現するのが少し厄介（quantity-based でも UI が誤解を招きうる）
- 既存営業資料（バトルカード / ROI 計算）の Lite 対応が広範囲

---

## 9. 着手判断

実装着手の意思決定条件:

- [ ] 経営層による smb-revised 提案の正式承認（Lite 新設・Starter 値下げ・Free 拡大の 3 本柱のうち最低 Lite が承認）
- [ ] Stripe ライブモードでの Lite Product 作成権限の確認
- [ ] 営業側で Lite プランの販売トーク・パンフレット準備の合意

承認後、**Phase 1 → 7 を 7 日（1.5 週間）で完遂**可能。Phase 1 のみ先行実装 → 内部 dogfooding → Phase 2 以降の判断、というインクリメンタル着手も推奨。

---

## 10. 関連ドキュメント

**営業資料** (Lite 反映済):
- [`docs/sales/pricing-plan-smb-revised.md`](../sales/pricing-plan-smb-revised.md) — Lite プランの営業提案 + 実装完了ステータス
- [`docs/sales/pricing-plan-current.md`](../sales/pricing-plan-current.md) — 現行プラン (Lite 行追加済)
- [`docs/sales/competitive-battlecards.md`](../sales/competitive-battlecards.md) — Section 5 vs Microsoft Defender for Business (Lite tier 比較)
- [`docs/sales/roi-calculator.md`](../sales/roi-calculator.md) — シナリオ 0 SMB 15 EP (Lite tier ROI)

**顧客向け公式**:
- [`docs/pricing.md`](../pricing.md) — Lite カラム追加済 (¥500/EP/月、5–45 EP)

**運用** (Lite 反映済):
- [`docs/billing/stripe-integration-guide.md`](../billing/stripe-integration-guide.md) — `STRIPE_PRICE_LITE` 設定 + per-EP 課金注意事項
- [`docs/ops/tag-release-procedure.md`](../ops/tag-release-procedure.md) — リリースフロー
- [`docs/ops/system-update-rollback.md`](../ops/system-update-rollback.md) — auto-update 失敗時の対応

**実装** (source of truth):
- [`server/internal/license/manager.go`](../../server/internal/license/manager.go) — `PlanLite` 定数 + `planFeatures[Lite]` + agent/user limits
- [`server/internal/billing/handler.go`](../../server/internal/billing/handler.go) — `STRIPE_PRICE_LITE` → `PriceMap`、Lite per-EP `agent_limit` 導出
- [`server/internal/middleware/plan_gate.go`](../../server/internal/middleware/plan_gate.go) — `RequireFeature` / `EnforceAgentLimit` + `requiredPlanFor` Starter 分岐
- [`server/internal/middleware/lite_e2e_test.go`](../../server/internal/middleware/lite_e2e_test.go) — Phase 6 E2E テスト
- [`server/internal/api/handlers/signup_handler.go`](../../server/internal/api/handlers/signup_handler.go) — Lite 5–45 / step-5 サーバ側 enforcement
- [`frontend/lib/usePlan.ts`](../../frontend/lib/usePlan.ts) — `Plan.Lite` + `planOrder.lite=0.5`
- [`frontend/app/signup/page.tsx`](../../frontend/app/signup/page.tsx) — Lite ボタン + 5 EP step 制約 + 比較マトリクス
- [`docs/openapi.yaml`](../openapi.yaml) — `Subscription.plan` enum に `lite` 追加
