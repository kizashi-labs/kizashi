# Windows / macOS 実行前防御・改ざん防止 設計（Linux 能動防御の横展開）

**作成日**: 2026-06-19
**対象**: 商用化優先課題①改ざん防止②実行前防御の **Windows / macOS 展開**
**前提**: Linux 版（eBPF LSM）で Ph0〜Ph6 を実装・実機実証・配布まで完了（[Linux改ざん防止と実行前防御設計.md](Linux改ざん防止と実行前防御設計.md)）。本書はその**運用モデルを各 OS のネイティブ機構へ移植**する設計。
**ステータス**: 設計フェーズ（コード未着手）

---

## 0. 移植する「動く運用モデル」（Linux で確立済み）

OS 非依存で再利用する枠組み（実装層だけ各 OS で差し替える）:

1. **protection_mode 申告**（enforce / observe / poll）を heartbeat でサーバへ → フリート可視化（実装済・`internal/protection` + `agents.protection_mode` + ダッシュボード）。
2. **audit → enforce の段階昇格**（per-endpoint opt-in env、既定 audit）。
3. **fail-open 既定**（機構が使えない/異常時は通す）。
4. **ルール源 = 既存 `process_block_rules`**（`action=alert`→audit / `block`→enforce）を全 OS 共通で再利用。
5. **disarm**（正規停止/更新の自己ロック回避）。
6. **判定の可観測化**（process_block イベント等で申告）。

→ 残るは各 OS の **「カーネル/特権機構で exec を同期拒否する」「agent を保護する」**実装層と、その**署名・配布ゲート**。

---

## 1. 現状（実コード）

| | Windows | macOS |
|---|---|---|
| プロセス観測 | ETW（Kernel-Process、opt-in `EDR_AGENT_ETW`）＝**ユーザーランド** | `process_collector.go` ポーリング／`process_collector_esf.go` は ESF スタブ（`darwin && esf`、未署名・未承認） |
| ネットワーク遮断 | `isolate_wfp.go` ＝実体は **netsh advfirewall**（WFP API/コールアウト driver ではない） | `isolate_pf.go`（pfctl） |
| カーネルドライバ | **無し** | **無し**（System Extension 未導入） |
| 実行前ブロック | 無し（事後 kill のみ＝`process_monitor.go`） | 無し（同上） |
| 改ざん防止 | userland バイナリ自己整合性チェックのみ | 同上 |

**含意**: 両 OS とも「観測＋事後 kill」止まり。真の実行前防御・改ざん防止には**新規のカーネル/特権コンポーネント**が要る。Linux の eBPF LSM（ドライバ不要）と違い、Windows/macOS は**ドライバ/System Extension＋ベンダー署名ゲート**が伴い、難度・コスト・期間が桁違いに大きい。

---

## 2. Windows 設計

### 2-1. 実行前防御（prevention）

Windows でユーザーランドからプロセス生成を同期拒否する手段は無い。選択肢:

| 機構 | exec 拒否 | 備考 |
|---|---|---|
| **プロセス生成コールバック driver**（`PsSetCreateProcessNotifyRoutineEx2`） | ✅ コールバックで `CreationStatus` を非0にして**生成をブロック**（Win10 1703+） | **第一候補**。カーネルドライバ必須。Linux LSM `bprm_check_security` に最も近い |
| **minifilter**（`FltRegisterFilter`） | △ ファイル `IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION` 等で実行ファイルの map を拒否 | ファイル I/O 層。exec 直接ではない |
| **WFP コールアウト driver** | ネットワークのみ | C2 接続のインライン遮断（現状 netsh の上位互換） |

→ **設計の核 = プロセス生成コールバックドライバ**。ルール（`process_block_rules` の絶対パス/ハッシュ）をユーザーランド service からドライバへ（DeviceIoControl）渡し、コールバックで照合 → audit（記録）/ enforce（`STATUS_ACCESS_DENIED`）。Linux の per-path mode + global enforce switch をそのまま移植。

### 2-2. 改ざん防止（tamper）

Windows EDR の標準手法:

- **PPL（Protected Process Light）**: agent service を anti-malware PPL として起動 → **非PPLプロセスからの kill / メモリ書込 / ハンドル取得を OS が拒否**（Linux の `task_kill` 保護に相当、より強力）。
- **ELAM（Early Launch Anti-Malware）driver**: PPL anti-malware として登録するための前提。ブート初期にロードされ、agent service の PPL 起動を許可。
- disarm: 正規停止は **PPL を解除できる権限（サービス制御 + 署名済みアンインストーラ）** 経由。Linux の SIGUSR1 disarm に相当する経路を Windows サービス制御で設計。

### 2-3. 署名・配布ゲート（Windows の最大コスト）

- **EV コードサイニング証明書**（組織検証、HSM 保管）。
- **カーネルドライバは WHQL / Attestation Signing**（Microsoft Hardware Dev Center 経由で Microsoft の署名が必要）。テスト署名はテストモード端末のみ。
- **ELAM driver は Microsoft の ELAM 署名**（別途申請）。
- → 配布は既存の `downloads/` バイナリ差し替えでは不可。**署名済みドライバパッケージ（.sys + .inf + .cat）＋インストーラ**が必要。

---

## 3. macOS 設計

### 3-1. 実行前防御（prevention）

- **Endpoint Security Framework（ESF）の AUTH イベント**: `ES_EVENT_TYPE_AUTH_EXEC` を購読し、`es_respond_auth_result(... ES_AUTH_RESULT_DENY ...)` で**exec を同期拒否**。Linux LSM bprm に最も近い、macOS 公式の実行前防御 API。
- 既存 `process_collector_esf.go`（NOTIFY 系の観測スタブ）を **AUTH 系へ拡張**。ルール照合は同様に `process_block_rules`。audit = `ES_AUTH_RESULT_ALLOW`＋記録 / enforce = `ES_AUTH_RESULT_DENY`。
- ⚠️ AUTH ハンドラは**期限内に応答必須**（タイムアウトで自動 allow＝まさに fail-open）。

### 3-2. 改ざん防止（tamper）

- **System Extension**（ESF は System Extension として動作）は **SIP（System Integrity Protection）配下で保護**され、ユーザーでも簡単には kill/unload できない。
- 正規のアンインストールは `systemextensionsctl` / MDM 経由 → disarm 経路として設計。
- TCC（Transparency, Consent & Control）でフルディスクアクセス等の許可も必要。

### 3-3. 署名・配布ゲート（macOS）

- **Apple Developer ID + Notarization**。
- **ESF entitlement `com.apple.developer.endpoint-security.client` は Apple の個別承認が必要**（申請ビジネスプロセス・数週間〜）。承認まで ESF は本番動作不可。
- **System Extension** 配布は MDM プロファイルでの承認が実務上ほぼ必須（ユーザー手動承認は摩擦大）。
- CGO 必須（ESF は C API）→ クロスコンパイル不可、macOS ビルドホストが要る。

---

## 4. OS 非依存層の再利用（差分は実装層のみ）

| 層 | 状態 |
|---|---|
| `protection_mode` 申告・集計・可視化 | ✅ 実装済（OS 非依存）。Windows/macOS の Detect() を拡張し各 OS の能力を申告（例: win=`driver_enforce`/`observe`、mac=`esf_enforce`/`observe`） |
| ルール源 `process_block_rules`（action→mode） | ✅ 共通再利用 |
| per-path mode + global enforce switch + fail-open | ✅ 設計パターン確立（各 OS のドライバ/ESF マップへ移植） |
| audit→enforce 段階・disarm・enforce opt-in | ✅ パターン確立 |
| 判定の process_block イベント申告 | ✅ 共通 |

→ **新規実装は各 OS の「拒否を実行する特権コンポーネント」と「署名・配布」のみ**。運用・サーバ・可視化は無改修で流用できる（Linux で整備済み）。

---

## 5. 段階ロードマップ（OS 別）

各 OS とも Linux と同じ audit→enforce 段階を踏む。**署名ゲートが先行ブロッカー**。

### Windows
| Ph | 内容 | 主リスク |
|---|---|---|
| W0 | プロセス生成コールバックドライバ PoC（テスト署名・テストモード端末で exec 拒否実証） | ドライバ開発・BSOD |
| W1 | ユーザーランド service ⇄ ドライバ通信（DeviceIoControl）、ルール配信、能力申告 | — |
| W2 | audit モード（記録のみ） | — |
| W3 | enforce（`STATUS_ACCESS_DENIED`）、fail-open 既定、per-endpoint opt-in | 誤ブロック |
| W4 | tamper：PPL + ELAM driver 登録 | ELAM 署名・自己ロック |
| W5 | **EV 証明書取得 + WHQL/Attestation + ELAM 署名 + インストーラ配布** | **署名ゲート（期間・費用）** |

### macOS
| Ph | 内容 | 主リスク |
|---|---|---|
| M0 | **Apple ESF entitlement 申請**（承認まで一切動かない＝最初に着手） | **Apple 承認（数週間）** |
| M1 | ESF AUTH_EXEC PoC（Developer ID 署名 + notarization、exec 拒否実証） | CGO・System Extension 承認 |
| M2 | audit → M3 enforce（fail-open＝AUTH タイムアウト allow） | 応答遅延での誤判定 |
| M4 | tamper：System Extension（SIP 保護）+ MDM 配布、disarm 経路 | TCC・MDM 承認 |

---

## 6. リスク・コスト比較（Linux 対比）

| 観点 | Linux（完了） | Windows | macOS |
|---|---|---|---|
| 防御機構 | eBPF LSM（**ドライバ不要**） | カーネルドライバ（生成callback）＋ ELAM | System Extension（ESF AUTH） |
| 署名ゲート | なし（CO-RE バイナリ） | **EV + WHQL/Attestation + ELAM 署名** | **Developer ID + notarization + ESF entitlement Apple 承認** |
| 致命的失敗 | verifier 拒否（安全側） | **BSOD** | カーネルパニック稀（ESF はユーザーランド寄り）／承認待ちで停滞 |
| ビルド | クロス可（committed/CI 生成） | ドライバは MSVC/WDK、CGO 不要だが driver build chain | **macOS ホスト必須・CGO** |
| 期間感 | 完了 | 中〜大（ドライバ + 署名で数ヶ月） | 大（Apple 承認が律速） |

**結論**: 運用モデル（audit→enforce/fail-open/mode 申告/disarm/ルール再利用）は Linux で実証済みでそのまま使えるため、**残りは各 OS の特権コンポーネント実装と署名・配布ゲートの突破**に集約される。難度・期間は Linux ≪ Windows ≈ macOS（理由はカーネルドライバとベンダー署名・Apple 承認）。

### 着手優先度の推奨
1. **macOS の ESF entitlement 申請を"今すぐ"開始**（承認が数週間の律速。コードより先に出す）。
2. Windows は **プロセス生成コールバックドライバ PoC（W0、テスト署名）**から。署名取得（W5）は PoC で実現性を確認してから投資。
3. 両 OS とも、まず audit モードで誤検知を実測してから enforce 昇格（Linux と同じ安全思想）。

---

## 関連
- Linux 版（実装・実機実証済み）: [Linux改ざん防止と実行前防御設計.md](Linux改ざん防止と実行前防御設計.md)
- 技術的負債台帳: [技術的負債と改善計画.md](../技術的負債と改善計画.md) P4-4
- 競合評価（防御モデルのギャップ）: [競合評価.md](../競合評価.md)
