# curate 衛生の恒久化と RuleEngine プラットフォーム・ゲート — 2026-07-02 セッション総括

[検知率向上と隠れた故障の是正_20260701.md](検知率向上と隠れた故障の是正_20260701.md) の続報。
前回総括が「残る検知率レバー」として挙げた **①FP自動隔離の `quarantined⟹disabled` 不変条件の破れ是正**
（同ドキュメント §6）と、技術的負債 P4-2 の教訓②として起票されていた **②RuleEngine の platform ゲート欠落** を、
検証EC2 の live 実測に基づいて根治した。いずれも**新規検知コードの追加ではなく、既存機構の整合・恒久化**。

---

## 1. curate 衛生: `quarantined ⟹ disabled` 不変条件の恒久化（PR #354）

### 発見（検証EC2 rules テーブル）
FP 自動隔離が効いているはずなのに、以下 2 種の `curate_state` 不整合が存在した:

| 不整合 | 件数 | 症状 |
|---|---|---|
| `quarantined` + `enabled=true` | 3 | **隔離が効かず ~200 件/24h の FP を発火し続けていた**（"File and Directory Discovery - MacOS" 等）|
| `deferred` + `enabled=true` | 96 | 実態は有効化済みの実検知だが状態ラベルが未追随（ロード数の水増しに見える）|

### 根本原因
`Quarantine`（`curate_service.go`）自体は `enabled=false` と `curate_state='quarantined'` を**原子的に**
セットしており正しい。破っていたのは**隔離後に `curate_state` を無視して再有効化する汎用トグル
（`RuleStore.Toggle`）と編集（`Update`）経路**。オペレータが「両刃のルールを使いたい」等で UI トグルすると、
隔離済みルールが `enabled=true` に戻り、状態ラベルだけ `quarantined` のまま残っていた。

### ★語彙の落とし穴（当初の想定が逆だった）
当初 `deferred` を「field 非対応=inert なので無効化してよい」と想定したが、**権威定義
（`server/internal/detection/curate.go` の `CuratePlan` / migration 278）では逆**:

- **`pending`** = field **非対応** = inert（false green）。有効化しても無意味。**inert なのはこちら。**
- **`deferred`** = field **対応**済みだが per-category cap 超過で次ラウンド待ち = **有効化可能な実検知**。

96 件の `deferred+enabled` は Linux Shell Pipe to Shell / Vim GTFOBin / PowerShell Cradles 等の実検知で、
一部は実テレメトリに発火中だった。**無効化はカバレッジ後退**になるため、実態に合わせ `curate_state='enabled'`
へ是正した（＝ロード数の「正確化」であって「削減」ではない）。`docs/ops/curate-soak-queries.sql` の
ヘッダにあった pending/deferred の逆転記述も本セッションで修正。

### 修正
- **DB 層で恒久保証**: `migration 292` の CHECK 制約 `rules_quarantine_disabled_check`
  = `curate_state IS DISTINCT FROM 'quarantined' OR enabled=false`。以後 Toggle/Update/手動 SQL の
  **どの経路からも隔離済みルールの再有効化は拒否**される（実機で UPDATE 拒否を確認）。
- **コード側**: `Toggle`/`Update` は明示 enable 時に `quarantined→'enabled'` へ引き上げ（オペレータ・
  オーバーライドとして扱い、制約違反 500 を回避）。まだ騒がしければ次ティックで FP 監視が再隔離＝自己修復。
- **既存不整合の是正**: quarantined+enabled 3 件は `enabled=false`（隔離実効化）、deferred+enabled 96 件は
  `curate_state='enabled'`。

運用手順・不整合検出クエリは [ops/段階curate運用.md](ops/段階curate運用.md)（新設「不変条件」節）と
[ops/curate-soak-queries.sql](ops/curate-soak-queries.sql) の [6] 節に反映。

---

## 2. RuleEngine の OS プラットフォーム・ゲート（PR #356）

### 症状
`RuleEngine.Evaluate` は `DetectionRule.Platform` を持ちながら**完全に無視**し、全ルールを全 OS の
イベントに評価していた。OS 固有ルールが他 OS のテレメトリに誤マッチする（上記 MacOS ルール FP の構造的原因）。

### 実測（検証EC2, 直近24h, 発火 agent OS × ルール platform）

| agent OS | rule platform | alerts/24h | 判定 |
|---|---|---|---|
| linux | linux | 2,334 | ✅ 正当 |
| linux | **windows** | **129** | ❌ FP |
| linux | **macos** | **113** | ❌ FP |
| windows | windows | 15 | ✅ 正当 |

→ **242 件/24h のクロス OS FP**。有効 sigma 内訳 windows 1,000 / linux 87 / **macos 43 + darwin 1** / universal 13。

### 修正（寛容設計＝誤検知だけ止め実検知は落とさない）
`Evaluate` ループに `platformMatchesEvent(rule.Platform, event.platform)` ゲートを追加:

- `platform` 未設定 or 全 OS 網羅（SigmaHQ の `logsource.product` 無し）= universal → 常に評価。
- event の `platform` が unknown/空 → **fail-open**。
- ★**`darwin ≡ macos` 正規化が必須**: agent は `runtime.GOOS` の `"darwin"` を報告するが SigmaHQ product は
  `"macos"`。等価比較のみだと **macOS ルールが macOS イベントにすら当たらなくなる**罠 → `canonPlatform` で吸収。

安全弁 `EDR_RULE_PLATFORM_GATE=0`（既定 ON）。詳細は [技術的負債と改善計画.md](技術的負債と改善計画.md) P4-5。

### ライブ実証
docker.yml デプロイ後、再起動後のアラートは `linux×linux` のみ。**`windows×linux`/`macos×linux` の
クロス OS FP はゼロ化**、正当検知は無傷＝純粋な FP 除去を実機で確認。

---

## 3. デプロイと反映状況

| 変更 | PR | main | 検証EC2 |
|---|---|---|---|
| curate 衛生（不変条件＋是正） | #354 | ✅ | ✅ 是正 DML＋制約を即時適用済。migration 292 は `schema_migrations` 記録済（冪等） |
| platform ゲート | #356 | ✅ | ✅ `docker.yml` dispatch（4イメージ＋`RUN_MIGRATIONS`）で detection 新イメージ反映・ライブ実証済 |

`migration 292` は `DROP CONSTRAINT IF EXISTS` ＋冪等 UPDATE で設計しており、手動即時適用と
`RUN_MIGRATIONS` 自動適用のどちらでも安全（再実行してもエラー無し）。

---

## 4. 結論

前回総括の「検知率を上げる本当のレバーは運用規律」を踏襲。本セッションも**検知能力の空白を埋めたのではなく、
既存機構の整合を恒久化**した:

1. **隔離の実効性**を DB 制約で保証（Toggle/Update からの再有効化を構造的に不能化）。
2. **クロス OS 誤検知**を platform ゲートで除去（242件/24h、真陽性の損失ゼロ）。

いずれも「作ったのに整合が崩れて効いていない」クラスの是正であり、前回の**サイレント故障カタログの延長**に位置づく。
`quarantined⟹disabled` と platform ゲートは、それぞれ CHECK 制約とテスト（`platform_gate_test.go`）で
**再発を構造的に防止**している。

## 付録: 本セッションで処理した PR
#354（curate 衛生: quarantined⟹disabled 不変条件＋curate_state 是正, migration 292）/
#356（RuleEngine OS プラットフォーム・ゲート）

---

**続き**: [検知率向上_20260703_fieldsupportロングテール消化.md](検知率向上_20260703_fieldsupportロングテール消化.md)
— field-support の false green を 93→0 まで消化（PE 情報 / IntegrityLevel / LogonId ＋ OR考慮ゲート根治 ＋ 回帰カナリア）。
