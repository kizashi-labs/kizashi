# EDR 競争力向上ロードマップ — 上位商用との差を埋める

**目的**: 構造・センサ深度は商用上位に肉薄している一方、**検知コンテンツの量・第三者ベンチ・スケール堅牢性・本番署名**が主な差。これを現状コードに即して優先順に埋める実装計画。

**現状の到達点（前提）**: Windows ETW＋カーネルドライバ（W0 実行前防御 / W4a 改ざん防止 / M2 注入 / M3 LSASS認証情報アクセス）、Linux eBPF LSM（実行前防御＋改ざん防止）、多エンジン検知（ビルトインSigma約116＋DBルール＋SequenceEngine相関）、UEBA、IOC/YARA/脅威インテリ、自動隔離・修復。①③センサ深度は実機E2E実証済。

**位置づけ**: `docs/技術的負債と改善計画.md`（負債台帳）・`docs/ATT&CK検知率測定計画.md`（採点基盤）の上位戦略版。各項目は現状ファイルに紐付け。

---

## 評価サマリ（率直な目安・厳密値ではない）
上位商用を100とすると:
- 設計・センサ深度: **70〜80**（カーネルセンサ＋能動防御＋ATT&CK整合を実機実証）
- 検知コンテンツ量・スケール実証・運用堅牢性: **30〜50**

→ 後者を埋めるのが本ロードマップ。レバレッジ順に P1→P4。

---

## P1: 検知コンテンツの自動拡充 ★最大レバレッジ
**進捗**: ✅ SigmaHQ週次自動同期（PR#297）— `SigmaSyncScheduler`をYARA同型で新設。手動トリガのみだったSigmaHQ同期を自動化、対応カテゴリ（DefaultSyncPaths）＋stable/testのみenable、変更時のみ`rules.invalidate`でライブ再読込。残: フィールド正規化のSigmaHQ網羅・取込ルールの自動トリアージ精緻化。

> ✅ **Phase A 解消済み（2026-06-26, commit 1e2a20d2）**: Engine の `addSigmaAliases` を AlertPipeline の `addPipelineSigmaAliases` に委譲して**フィールド正規化を単一層に統一**。detection-server も registry(TargetObject/Details/EventType)・image_load(ImageLoaded/Signed)・script(ScriptBlockText)・Hashes合成・Image basename正規化を適用するようになり、RuleEngine の `sigma.Config.FieldMappings`(基本フィールド多ターゲット探索)と相補的に働く。**同期ルールを curate 有効化すれば detection 側で正しく評価される状態**になった。ドリフト再発防止に `TestAddSigmaAliases_DetectionParity` 追加。残=同期ルールの段階 curate 有効化(Phase C)。
>
> ⚠️ **Phase A の背景（2026-06-26 コード調査で確定）**: 検知は「2パイプライン×3テーブル」に分裂している。
> - SigmaHQ同期の出力先は **`rules` テーブル → detection-server の `RuleEngine` のみ**が読む（`enabled=true`）。api-server の `SigmaEvaluator`（`[Sigma]`アラート）は `yara_rules`+`custom_alert_rules` を読み、同期ルールを一切見ない。
> - フィールド正規化に**非対称**がある。api-server は `addPipelineSigmaAliases`（registry `TargetObject`/`EventType`/`Details`、image_load `ImageLoaded`/`Signed`、script `ScriptBlockText`、`Hashes`合成、Image basename `\`前置）を持つが、**detection-server の RuleEngine は `sigma.Config.FieldMappings`（[rule_engine.go:75](../server/internal/detection/rules/rule_engine.go)）に process/file/network/dns/auth の基本のみ**で、上記 registry/image_load/script/Hashes/basename が**欠落**。
> - 結論: registry/image_load/script 系の同期ルールを今 `enabled=true` にすると **detection 側でフィールド不一致のまま静かに inert**（＝誤った緑）。**Phase A = alias ロジックを両パイプライン共有の単一正規化関数に抽出し、`engine.go processMessage`（`normalizeCommandLine` 直後）でも適用**してパリティ化すること。これ無しに curate 有効化は効果が出ない。

**差**: ビルトインSigma約116＋ヒューリスティック vs 商用の数千＋日次更新。

**現状（強み）**: 公開検知コンテンツの自動同期パターンが既にある —
- `server/internal/scheduler/yara_sync_scheduler.go` が **Yara-Rules/community を自動同期**（実績: `imported/updated/failed` ログ、約11,800ルール）。
- ルール取込/書出: `rules_ie_handler.go` / `sigma_handler.go` / `sigma_db.go` / `store/rules.go`。
- フィールドマッピング監査・隠れMISS修正の実績（検知率向上スプリント）。

**具体ステップ**:
1. **SigmaHQ 自動同期スケジューラ**を `yara_sync_scheduler.go` と同型で新設（`sigma_sync_scheduler.go`）。SigmaHQ 公開ルールを取得→`sigma_db` へ取込→`AlertPipeline`/`engine` のSigmaエンジンが反映。
   - 取込時に `sigma_builtins_health_test.go` のmalformed検査＋`primary_technique_test` を自動ゲート（壊れたルールを弾く）。
   - フィールド名の正規化レイヤ（既存 `alert_pipeline.go` の alias）を SigmaHQ のフィールド名（`TargetObject`/`Image`/`CommandLine`等）に合わせて拡充。
2. **取込ルールの自動トリアージ**: 対応テレメトリ型が無いルール（例: ETW未収集のフィールド）は「準備中」タグで隔離（誤った緑を防ぐ）。`docs/センサ被覆と深度監査.md` のセンサ対応表と突合。
3. **ルール品質ゲートのCI化**: health/primary-technique テスト＋少数の合成イベントでの発火テストをマージゲートに。

**工数**: 中（YARA同型のスケジューラ＋フィールド正規化）。**効果**: 検知数を桁で増やせる。最優先。

✅ **Phase B/C 中核 完了（2026-06-26, commit e2fa1240）= curate判断ロジックを本番化**:
- **フィールド対応ゲート本番化** (`field_support.go`): `SupportedSigmaFields()`/`RuleSelectedFields()`/`RuleFieldSupport(yaml)→(supported,unsupported[])`。テレメトリ(native+alias)が埋められないフィールドを選択するルール=inert(false green)→有効化禁止を判定。既存 audit テストは本番関数を使うよう refactor。★Phase Aでregistry/image_load/script正規化済なのでそれらのカテゴリが「対応」判定可能に。
- **段階curate選定** (`curate.go`): `CurateBatch(rules, perCategoryLimit, supported)→{Enable/Deferred/Pending}`。フィールドゲート(未対応=Pending)+カテゴリ別上限(reload flood回避、超過=Deferred、ID順で決定的=ラウンドで前進)。純ロジック・CI実行可・テスト網羅。

✅ **ライブ実証 完了（2026-06-26, 検証EC2）**: 本日全コミット(Phase A含む)をEC2へ手動デプロイ(`git pull`→`docker compose build detection api`→`up -d`、api/detection healthy)。
- **定量化**: `cmd/curate-analyze` で実コーパス実測=**2057同期ルール中 1262 が field-supported(=検知ルール ~106→~1368, 12.6×)**。
- **★end-to-end発火実証(before/after)**: Phase A**未**デプロイ時は `whoami /priv` 等のImageアンカー同期ルールが**0件発火**(basename問題)→**デプロイ後は同操作で `[SIGMA] Security Privileges Enumeration Via Whoami.EXE`/`Group Membership Reconnaissance`/`Nltest.EXE Execution` が発火**。curateがend-to-endで機能。
- **スケール実証**: Phase A解放カテゴリ523件(registry/script/image_load/dns/file)を有効化→検知ルール **106→632(6×)** をhealthyロード(compiled=618、"too many clients"無し)、FPフラッド無し。
- 実証後はベースライン(106)へロールバック(本番curateはFPチューニングを伴う段階運用として別途)。**サーバコードは最新デプロイ済のまま**。

✅ **Phase C 本番化 完了（2026-06-27, commit 273c9e85）= curate を CLI/手動SQL から製品内 API + 自動スケジューラ + FP 自動隔離へ昇格**:
- **migration 278**: `rules.curate_state`(pending/deferred/enabled/quarantined)+curated_at/quarantined_at/quarantine_reason+partial index。NULL=非curate管理(seeded/custom/builtin)。
- **`detection.CurateService`** (`curate_service.go`): `Status`(カテゴリ別 total/supported/enabled/deferred/pending/quarantined を field ゲートから live 集計)/`RunRound`(supported を cap で1ラウンド有効化→`rules.invalidate`)/`MonitorFP`(curate-enabled 限定で window 内 閾値超ルールを自動隔離)/`Quarantine`。純 decision は既存 `CurateBatch`。
- **管理 API**: `GET /api/v1/admin/detection/curate/status` / `POST .../run {categories?,cap?}` / `POST .../quarantine {rule_ids,reason}`(admin限定)。
- **`scheduler.CurateScheduler`**: 毎tick「FP監視→(opt-in)1ラウンド前進」。順序=ノイズ清掃→拡大で不良ラウンドを封じ込め自己調整。env: `CURATE_AUTO_ENABLE`(既定true)/`CURATE_ROUND_INTERVAL_MIN`(360)/`CURATE_PER_CATEGORY_CAP`(20)/`CURATE_FP_WINDOW_HOURS`(24)/`CURATE_FP_THRESHOLD`(50)。
- **★検証EC2でライブ運用化**: auto OFF で手動3ラウンド(registry/script/image/process_creation)→各ラウンド **FP=0** を確認しつつ検知ルール **Sigma compiled 133→369(2.8×)** 拡大→納得後 **auto ON 切替**(override 削除)。以降 6h ごとに自動拡大+FP 自動隔離。運用手順は [ops/段階curate運用.md](ops/段階curate運用.md)。
- 🔲 残（任意）: 管理 UI(sigma-rules 画面 or 専用ページ)での curate 状態可視化(今回サーバ側先行)。[検知ルールの二重管理とデプロイ.md](検知ルールの二重管理とデプロイ.md)の単一ソース化(案A)は別途。

---

## P2: MITRE Evaluations 準拠の自己採点強化
**進捗**: ✅ 多段チェーン採点（PR#299）— runlog の任意列 `scenario` で攻撃連鎖をグルーピングし段ごとに集計＋チェーン断ち切り率。✅ 3軸完成（PR#302）— Protection軸（enforce阻止を alert 文言で判定）を追加し Visibility/Detection/Protection の3軸を MITRE Evals 形式に。

✅ **P2①②完了（2026-06-26, commit eb5c25e9/2289b02c）**:
- **tactics マップ拡充**: ~60→~110技。実測で欠落していた discovery(T1069/T1049/T1007/T1012/T1135/T1482等)/exfiltration/execution/lateral/C2/impact を網羅。未知技が tactic 空で Tactic 昇格不可だった問題を解消。
- **サブテク精密採点**: `sameTechnique` を完全一致 or 片側基底のみ→Technique、別サブテク同士→Technique不可(Tactic止まり)に。従来の基底一致(T1059.001==T1059.003)の甘さを Evals 流に厳格化。
- **scenario 列駆動**: `run-atomics.ps1 -Scenario` / `run-atomics.sh out.csv <名>` で全技をチェーンタグ付け。scorer 側は実装済だったが runner が出力せず scoreChains を回せなかった構造的欠落を解消。+ loadRunlog の欠落任意列バグ修正(scenario無し旧runlogが誤チェーン採点になっていた)。
- **定点観測**: `-baseline <前回csv> -baseline-tol <pt>` で率低下を回帰検出し exit 3(CIゲート化可能)。

✅ **P2③ CI定点観測 完了（commit 0d9891ae）**: `-alerts <json>` オフライン採点モード(server不要・決定的)+ `docs/results/`(fixture+baseline)+ `attack-scorecard.yml`(push/PR/dispatchでfixtureをオフライン採点しbaseline比較、率低下でexit 3)。採点ロジックの退行を毎push自動検出。**P2完了**(残: ライブ実測の`docs/results/live-*.csv`蓄積は運用 / `isBlocking`文字列マッチ改善は任意)。

**差**: attack-scorer は**単一イベント単位**の自己測定。商用は ATT&CK Evaluations（実攻撃チェーンを第三者採点）受験済。

**現状（強み）**: `agent/cmd/attack-scorer/`（main.go/tactics.go）が runlog × アラート/イベントを突合し**ランク（None/Telemetry/General/Tactic/Technique＋Blocked）＋KPI（可視性/検知/解析検知/防御/MTTD/FP）**を算出。Atomicランナー（`agent/scripts/run-atomics.ps1/.sh`）あり。`docs/ATT&CK検知率測定計画.md` にルーブリック。

**具体ステップ**:
1. **多段チェーン採点**: 単発Atomicでなく **ATT&CK Evaluations 形式の連鎖シナリオ**（例: 初期アクセス→偵察→認証情報→横展開→C2→Exfil）を実行し、ステップ毎にランク＋全体カバレッジを採点。`run-atomics` を「シナリオ定義（YAML）」駆動に拡張。
2. **3軸採点の明確化**: Visibility（テレメトリ有無）/ Detection（アラート化）/ Protection（enforce阻止）を分離集計。`SequenceEngine` の多段検知をTactic/Techniqueランクに正しく反映。
3. **定点観測**: スプリント毎にスコアを記録し回帰検出（P1で増えたルールの効果を数値化）。`tactics.go` のtechnique→tacticマップをサブテクニックまで拡充。

**工数**: 中。**効果**: 「他社比どの程度か」に**自社内で再現可能な根拠**を持てる（真のMITRE Eval受験は別途・有償）。

---

## P3: 本番ドライバ署名の調達計画（W5・外部依存）
**進捗**: ✅ 工学的成果物を整備（PR で追加）— ① **調達ランブック** [docs/ops/Windowsドライバ本番署名 調達ランブック.md](ops/Windowsドライバ本番署名%20調達ランブック.md)（EV証明書→Partner Center→Attestation→WHQL の段階・コスト・対象OS・CIシークレットを実行手順化、推奨=Azure Trusted Signing）。② **CI署名足場** `.github/workflows/agent-driver-windows.yml`（workflow_dispatch、driver build→署名はシークレット存在時のみ、無ければ未署名アーティファクト）。残（=**業務手続き、エンジニア作業外**）: EV証明書発注・組織検証・Partner Center登録・Attestation/WHQL提出。

**差**: ドライバは testsigning 止まり → 実顧客エンドポイントへ配布不可。

**現状**: `docs/design/Windows改ざん防止と本番署名設計.md` に W4b(PPL+ELAM)/W5(EV+WHQL) を設計済。Linux eBPF は署名不要で配布可（`agent-ebpf.yml`）。

**具体ステップ（調達・手続き中心、コード少）**:
1. **EV コードサイニング証明書**の調達（組織検証・HSM必須）。
2. **Microsoft Partner Center** 登録 → ドライバの **Attestation Signing**（軽量）または **WHQL**（重い・互換ラボ）でMS発行署名を取得。
3. CIに本番署名ステップを追加（現 `agent-ebpf.yml` のLinux配布に倣いWindowsドライバ配布パイプライン化）。
4. **PPL+ELAM**（W4b）は anti-malware EKU 証明書（MS発行）取得後にagent/ドライバ自体の停止・ブート時保護を有効化。

**工数**: 小（コード）＋調達リードタイム大。**効果**: 「PoC/検証環境のみ」から「実顧客配布可能」へ。商用化の必須ゲート。

---

## P4: 脅威インテリの拡充とレピュテーション
**進捗**: ✅ 公開フィード自動取込（PR#300）— FeedSchedulerがabuse.ch(URLhaus/MalwareBazaar/Feodo)/OTXの実スキーマを `internal/intel` パーサに委譲（従来はプレーン行誤パース）、migration275でfree公開フィードを有効化。

✅ **P4① IOC列分断バグ根治 + 多ソース・レピュテーション（2026-06-26, commit c7f49015）**:
- 🔴**根治**: FeedScheduler の全 INSERT が `type` だけ設定し `ioc_type` を NULL のままにしていた → DBポーリング型マッチャ(`scheduler/ioc_matcher.go`は`ioc_type`を読む)が**実測 23,379件 全件をフィードIOC取りこぼし**。共有 `upsertIOC` に集約し type/ioc_type 同時設定 + migration277で再バックフィル。**ライブDB実証: NULL 23379→0**。
- **多ソース・レピュテーション(confidence)**: 同一IOCが複数フィードに一致するほど confidence 上昇(新規ソース→+15上限100、source_count/sources追跡、同一ソース再取込は据え置き)。detection で IOCアラートに「信頼度 N/100」露出 + 高信頼(>=75)は severity+1。**ライブDB実証: 2ソースで 50→65**。
残: 新フィード追加（abuse.ch ThreatFox 等）、エンリッチの多テーブル統合(`threat_intel_iocs`/`ioc_entries`)、(将来)挙動ML。★新コードのEC2デプロイで FeedScheduler が今後の取込に ioc_type/confidence を設定(migration277は手動適用済=既存23k修正済、デプロイで恒久化)。

**差**: ローカルヒューリスティック＋UEBA中心 vs 商用のグローバルテレメトリ規模ML/レピュテーション。

**現状（強み）**: 既に厚い — `taxii_handler.go`/`stix_handler.go`/`threat_feeds_handler.go`/`threat_intel_handler.go`/`ioc_enrichment_handler.go`、`engine.go` の脅威インテリ照合（T1071）。

**具体ステップ**:
1. **公開フィードの自動取込拡充**: abuse.ch（URLhaus/MalwareBazaar/ThreatFox）、AlienVault OTX、CISA等をTAXII/STIX経路に追加し定期同期（YARA/Sigma同期と同型スケジューラ）。
2. **IOCレピュテーション/エンリッチ強化**: `ioc_enrichment_handler.go` を多ソース照合（ハッシュ/IP/ドメイン/URL）に拡張、信頼度スコア付与。
3. **（大規模・将来）挙動ML**: UEBAベースラインを越えた、クロスエンドポイント挙動モデル。グローバルテレメトリが無い自前環境では限定的 → サードパーティMTD/インテリ連携で補完が現実的。

**工数**: 小〜中（1-2）＋大（3）。**効果**: 既知脅威の即時ブロック率向上。

---

## P0（横断）: 運用堅牢性 — ライブ検証の自動化
**進捗**: ✅ 第一弾=type別検知の回帰スイート（PR#296）— `engine.typedFindings` 抽出＋6ソース発火/非発火＋RuleID=""のsilent-breakガード。✅ 第二弾=実行時死活監視（PR#298）— `edr_alert_insert_failures_total{source}` でINSERT失敗を可視化（`rate>0`でアラート化）。✅ **第三弾（2026-06-26, commit e518b9d2）= 合成注入E2EのCI化 + メトリクス穴補完**:
- **メトリクス穴補完**: `edr_alert_insert_failures_total` は汎用ルール+typedFindings+AlertPipeline(sigma/ioc)しか計上しておらず、**Engine の IOC/ML chain/baseline/cloud の SaveAlert 失敗が未計上**だった（engine.go の4経路）。`.Inc()` を追加し source ラベルを `DetectionsByEngine` と一致（cloud/ioc/chain/baseline）。
- **合成注入E2E**: `synthetic_injection_integration_test.go`（build tag=integration）が crafted NormalizedEvent を**実 `AlertPipeline.handleEvent` → 実 Postgres INSERT** に流しアラート行の永続化を検証。pure-logicオラクルが見れない**DB制約由来のsilent fail**（22P02/CHECK/42P08）と**alias欠落でルールinert**のクラスを捕捉。registry+fileの2ソース、注入後ゼロ件はhard fail。
- **nilガード**: `publishAlertCreated`/`publishIncidentCreated` を nil nc で安全化（publishはベストエフォート）。
- **CI配線**: `ci.yml` の Server Tests に「Synthetic injection E2E (integration)」ステップ追加（既存postgresサービス再利用、コンテナビルド無し）。

✅ **第四弾（2026-06-26, commit 3b31235d）= P0残3項目を完了**:
- **process_block 消費者**: ingestion→DB永続化されるが検知消費者ゼロでアラート0だった予防通知を typedFindings に case追加し [BLOCKED]アラート化（Protection軸にも乗る）+ 回帰ユニットテスト。
- **検知死活監視**: `deploy/prometheus/rules/edr-alerts.yml` に `EDRDetectionInsertFailures`(critical, `rate(edr_alert_insert_failures_total[15m])>0` source別=silent-break即検出) と `EDRDetectionPipelineSilent`(warning, 全エンジン1h無検知=パイプライン死canary)。既存メトリクス直結でコード変更不要。※`alerts.source`列はmigration270で既存だが、死活監視はカウンタ方式を採用(列集計不要)。
- **Engine E2Eシーム**: `processMessage` を `processEventData(ctx, data []byte)` に分割し将来のjetstream.Msg無しE2Eの継ぎ目を用意。フルEngine E2Eは store adapter が cmd/detection(package main)で再利用不可のため見送り、実INSERT(空RuleID→NULL)は既存 internal/store 統合テスト・typed検知ロジックはユニットテストでカバー。

**P0=実質完了**。残（任意・低優先）: AlertPipeline E2Eのソース拡張(dns/cred)。フルEngine E2E（要 adapter を共有パッケージへ移動）。

**差の核**: 今セッションのライブ検証で**実本番バグ**が複数露見（api パイプライン誤診・dedup pgxバグ・6検知ソース断線・レジストリ値欠落）。商用上位は概ね潰し済の領域。

**具体ステップ**:
1. **合成注入E2Eテストの自動化**: 各検知ソース（registry/dns/cred/process_block/memory等）について「合成イベント投入→アラート生成」を ingestion gRPC 経由でCIに組込（core `nats pub` は durable pull consumer にスキップされるため**実ingestion経路必須** ＝今回の教訓）。
2. **検知ソース死活監視**: 各 `source` の最終アラート時刻を監視し断線を検出（`project_security_dashboards_real_data` の自動コレクタ拡張）。
3. **回帰ゲート**: P1のルール増加・P2のスコアを毎マージで測定。

**工数**: 中。**効果**: 「動いているはず」を「動いている」に。成熟度の底上げ。

---

## 推奨実行順
1. **P0（堅牢性の自動E2E）** — 以降の全改善の土台。まず断線を二度と起こさない。
2. **P1（Sigma自動拡充）** — 検知量を桁で増やす最大レバレッジ。
3. **P2（チェーン採点）** — P1の効果を数値で可視化、回帰防止。
4. **P4-1/2（フィード拡充）** — 既存基盤の延長で低コスト高効果。
5. **P3（本番署名調達）** — 商用配布の必須ゲート、リードタイム長いので並行着手。

各Pは独立に着手可。P0→P1→P2 の順で「堅牢な土台→量→可視化」のループを回すのが最短。

## ★2026-07-01 の到達点: 検知能力は包括的に完成、残る差は「運用」

検知率向上スプリント（詳細 [検知率向上と隠れた故障の是正_20260701.md](検知率向上と隠れた故障の是正_20260701.md)）で、
**実コードを確認した上での重要な結論**が得られた:

- **検知能力に未実装の空白は無い**。image_load 署名 / LSASS(T1003) / AMSI(難読化スクリプト) / クラウド・ID 検知は
  いずれも既に実装済み（「新規追加」を検討するたびに既存が見つかった）。
- 検知率を制限していたのは **①サイレント故障（作ったのに壊れている、12件超）②未デプロイ ③未有効化（curate）
  ④未計測**。本スプリントで①を根治＋CIゲート化、②③④を前進（curate +103ルール、live 実測 可視性100%/検知率80%/
  解析検知30% をベースライン記録）。
- ★**競争力評価の更新**: 「設計・センサ深度 70-80」は妥当だが、その実力が**運用の穴で出せていなかった**のが実態。
  差を埋める本質は**新規検知コードでなく運用規律**（curate ソークの長期反復 / 端末デプロイ / FP チューニング /
  フィールド契約ゲートによる回帰防止 / 第三者 MITRE Evals 受験）。P1(量)・P2(可視化) は「作る」より
  「有効化・計測・維持」のループに軸足を移す段階に入った。

## ★2026-07-02 の到達点: 検知率は「agent テレメトリの被覆幅」で律速される

7-01 の「未有効化」を掘り下げると、有効化されているのに参照フィールドをテレメトリが emit せず**構造的に一度も
発火し得ない "false green" が 132 件**あった（詳細 [検知率向上_20260702_fieldフロンティアと自己点検カナリア.md](検知率向上_20260702_fieldフロンティアと自己点検カナリア.md)）。
欠落フィールド別に集計すると `OriginalFileName=74 / Initiated=41` と優先順位が明確で、**単一の agent フィールドを
1 つ emit するだけで数十のルールが一斉に有効化**する＝新規ルール作成より桁違いに高 ROI のレバーがここにあった。

- **P1 の性格が変わった**: サーバ側検知資産は飽和に近く、検知量の次のレバーは **agent がどれだけ多様なフィールドを
  emit するか**（テレメトリ被覆幅）へ移った。`Initiated` はサーバ側エイリアスで即解消（PR #367, +41 network ルール）、
  false green は 132→93→（7-03 で）0 まで消化。残る最大レバーは `OriginalFileName`=74 ルール（agent の PE VERSIONINFO 抽出）。
- **「次に足すべきフィールド」を生きたロードマップ化**: `field-support.go` の静的判定を CurateScheduler の常駐カナリアに
  昇格。`FieldGapReport`＋`CurateFieldGap{field}`（PR #371）が **どのフィールドを足せば何ルール有効化するかを Grafana に
  常時ランキング表示**する。運用者は数字の大きいフィールドから順に agent の emit を足せばよい。false-green（即時, PR #387）/
  inert（1 週間ゼロ発火, PR #357）と併せ 3 カナリアで有効化集合の field 契約の腐敗を継続監視。
- ★教訓＝**静的被覆 ≠ 有効化 ≠ 実際に評価されている**。同教訓の Prometheus 版＝ルールディレクトリ未マウントで全アラート
  沈黙（PR #360）。P1(量)は「ルールを増やす」から「テレメトリのフィールドを増やし、その効果をカナリアで常時可視化する」へ。
- **★2026-07-13 追記＝カナリア初ライブ計測で field 被覆軸が飽和と確定**（詳細 [検知率向上_20260713_PowerShell4103モジュールログ.md](検知率向上_20260713_PowerShell4103モジュールログ.md)）。
  `FieldGapReport` を検証EC2 実 DB に読み取り専用で実行 → enabled 1981 中 false-green は **28 のみ（98.6%）**。残 top レバー
  `Payload=22/ContextInfo=3`＝PowerShell Module Logging (4103) を **PR #458 で実装・消化**（`ETWPSModuleCollector`、既存 4104
  経路不変）。残った exotic な Cobalt Strike named-pipe も **翌 2026-07-14 に PR #464 で消化**（`ETWPipeCollector`＝Kernel-File
  の Create から `\Device\NamedPipe\` を抽出し `pipe_name→PipeName`。custom ソースゆえカナリアに映らなかった最後の 1 件。
  [検知率向上_20260714_named-pipeテレメトリ.md](検知率向上_20260714_named-pipeテレメトリ.md)）。**P1 の field 被覆軸は完全に
  クローズ**（4103=#458 / named-pipe=#464）し、検知率のフロンティアは field でなく**別軸の運用信頼性**（ライブ発火の
  detection-engine consumer ラグ＝「保存されるのに検知されない」）へ完全に移った。

## ★2026-07-03 の到達点: Windows 能動計測 Technique 100%（唯一の技法ギャップを解消）

7-02 計測（[results/live-20260702-windows-discovery.md](results/live-20260702-windows-discovery.md)）で唯一 Technique 未達だった **T1112(Modify Registry)** を解消し、ディスカバリ/実行/永続化 13技が **Technique 92.3% → 100%** に到達。

- **原因**: 既存 T1112 ルールが Run キー（`reg add ...CurrentVersion\Run`）限定で、汎用 HKCU への `reg add` を捉えられず Tactic 止まりだった。
- **修正**: level:low builtin Sigma「Registry Modification via reg.exe」（`attack.t1112`, PR #373）を追加し `reg.exe add` で HKCU/HKLM/HKU への書込を汎用被覆。高価値キー（Run/Defender/UAC/Winlogon）は既存の高 severity ルールが役割分担。
- **実機実証**: docker.yml で server-api 反映 → 検証EC2 Windows box で汎用 `reg add` → 本番 AlertPipeline が T1112 発火（MTTD ~1.5s）→ attack-scorer 再採点で **T1112=Technique**。
- ★教訓: **attack-scorer の Technique 判定はアラートの `mitre_technique`（=最初の `attack.t*` タグ）一致で決まり level 非依存**。builtin ルールは curate の FP 自動隔離対象外（`source='sigmahq'` のみ）ゆえ、汎用ノイジー技は level:low に留め FP を低優先度トリアージへ抑える設計とした。

## ★2026-07-06〜08 の到達点: 運用可観測性の4層 + 検知品質の横断整備

「残る差は運用」（上記2026-07-01の結論）を受け、検知以外の4軸（対応自動化/相関・UI・パフォーマンス・商用readiness）を横断的に整備。**12 PR をマージ**（テスト2件を除きデプロイ・ライブ実証済）。競争力上の意味は、**「プロセスが生きている」だけでなく「機能が実際に動いているか」を各層で監視・保証できるようになった**こと（サイレント障害クラスの根絶）。

### 運用可観測性の4層（商用readiness の核）
| 層 | 内容 | PR / メトリクス |
|---|---|---|
| プロセス生存 | worker(detection/ingestion)に liveness/readiness プローブ（`/healthz`=生存、`/readyz`=DB+NATS到達性を検証し断で503）。旧: `/health`が無条件200で「DB/NATS断でも健全」と誤報 | #425 |
| デプロイ無損失 | ingestion gRPC グレースフルシャットダウン（SIGTERMで GracefulStop、受信済みイベントをドレイン）。旧: SIGKILLで処理中イベント喪失＝ローリング更新毎に検知漏れ | #427 |
| バックアップ健全 | pg_dump 整合性検証（完了マーカー確認）+ SLO メトリクス `edr_backup_last_success_timestamp_seconds`/`edr_backup_failures_total`。旧: exit0なら中身未検証で「completed」＝復旧時に壊れたダンプ発覚 | #430 |
| 検知機能生存 | 検知パイプライン dead-man's-switch `edr_detection_last_event_timestamp_seconds` + バックプレッシャー `edr_detection_consumer_pending`。プロセス生存でも ingestion→NATS→detection 停滞を捕捉 | #434 |

いずれも [監視ランブック.md](ops/監視ランブック.md)（アラートルール `EDRDetectionPipelineStalled`/`EDRBackupStale` 等）・[バックアップ・リストア.md](ops/バックアップ・リストア.md)・[パフォーマンスチューニング.md](ops/パフォーマンスチューニング.md)・[Kubernetes本番ガイド.md](ops/Kubernetes本番ガイド.md) に反映済み。

### 検知品質・相関・性能の横断整備
- **FP 横断ハードニング（#415）**: Engine 経路の dedup 欠落を根治（状態系ルールが8日で367,502件を氾濫→`isDuplicateAlert`で収束、`edr_alerts_deduped_total`で可観測化）。ML異常検知の z-score 直写像を severity 上限で抑え、頻度異常だけの自動隔離リスクを除去。
- **インシデント相関の再設計（#417）**: (agent,technique)毎の分割＋毎時churn（1,255件累積）を、agent×窓の**多段ケース**に束ね直し、構成アラートを紐付け（ドリルダウン復活）。UIに ATT&CK キルチェーン可視化（#421）。
- **自動対応の修正（#418）**: remediation cooldown が rule-global で拡散攻撃の後続ホスト隔離をスキップ→(rule,agent)単位に修正。
- **書き込み性能（#422/#424）**: イベント取込を per-event→マルチ行INSERT、alerts/events の完全重複索引6個削除。
- **テストカバレッジ（#438/#439）**: notification 8.7→29.6%、siem 22.5→42.4%。

### 副次的に発見・修正したバグ
- baseline のカーネルスレッド(kworker)誤検知（別セッションで #419/#420 修正）。
- SIEM 転送の severity 写像バグ（`/10` で sev-9 が CEF 0 に潰れる→別セッションで #440 修正）。

**残る商用readinessの穴**: 本番環境そのものの構築（インフラ）/顧客環境サーバ自動アップデート機構（設計済・大規模）。いずれも「コードの穴」ではなく調達・インフラ・大規模実装の領域。

## メンテ
スプリント毎にP2スコアを記録し本書を更新。各P着手時に対応ファイル/PRを追記。
