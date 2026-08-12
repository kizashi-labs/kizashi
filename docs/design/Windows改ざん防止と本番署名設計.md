# Windows 改ざん防止（tamper）と本番署名 設計（W4 / W5）

**位置づけ**: [Windows・macOS実行前防御と改ざん防止設計.md](Windows・macOS実行前防御と改ざん防止設計.md) の Windows W4（改ざん防止）/ W5（本番署名）の詳細設計。
W0〜W3（実行前防御ドライバ・agent 統合・NT→DOS 照合・mode 申告）は
[../Windowsカーネル防御PoC手順.md](../Windowsカーネル防御PoC手順.md) を参照（W0 実機実証済み）。

改ざん防止は **2 層**に分ける。**W4a はテスト署名で実機検証可能**、**W4b/W5 は MS 発行証明書に依存**するため設計・手順化に留める。

---

## W4a: Ob コールバックによる kill 拒否（✅ 実機実証済み 2026-06-20）

> ✅ **実機実証済み（2026-06-20, Windows Server 2022 EC2, テストモード）**: tamper 入りドライバを
> ビルド→テスト署名→ロード（RUNNING）。`wintamper-poc -pid <notepad> -enforce` で保護 →
> 別シェルの `taskkill /F /PID <notepad>` が **「Access is denied」で失敗**、ハーネスに
> `tamper: target_pid=... enforced=1 access=0x1401`（要求された `PROCESS_TERMINATE` を剥奪）。
> **audit/enforce 対比も実証**（同一セッション）: audit（`-enforce` 無し）では同一のハンドル要求
> （`access=0x1401`＝`PROCESS_TERMINATE` 含む）を**検知のみ・許可**（`enforced=0`）で `taskkill` が
> `SUCCESS` → 段階制御（fail-open→enforce）が機能。Linux eBPF LSM `task_kill` deny の Windows 版が成立。


### 何をするか
KizashiPrevention ドライバに `ObRegisterCallbacks` のプロセスハンドル**事前操作コールバック**を追加し、
**保護対象（agent 自身の PID）へのハンドル**から危険なアクセス権を剥奪する。Linux eBPF LSM の
`task_kill` 拒否の Windows 版で、**audit→enforce / fail-open / disarm** の思想は完全に同型。

剥奪するアクセス（`PREV_TAMPER_STRIP`）:
`PROCESS_TERMINATE | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD |
PROCESS_SUSPEND_RESUME | PROCESS_SET_INFORMATION`
→ kill・コードインジェクション・サスペンドを防ぐ。

### 制御モデル
- **fail-open 既定**: `TamperEnforce=0` では剥奪せず、試行を記録するのみ（audit）。
- **enforce opt-in**: agent が `EDR_TAMPER_ENFORCE=1` のとき `SET_TAMPER` で enforce=1。
  かつ保護 PID の mode が `PREV_MODE_ENFORCE` のときだけ剥奪。
- **自己ハンドル除外**: 保護プロセスが自分自身を開く場合は剥奪しない。
- **エスケープハッチ（自己ロック回避）**:
  1. **graceful stop**: agent は `ctx` キャンセル（SCM stop / Ctrl-C）時に `SetDisarm(true)` してから終了。
  2. **ハード**: `sc stop KizashiPrevention` でドライバを停止 → `ObUnRegisterCallbacks` で保護解除。
     管理者は常に回復可能。Linux の SIGUSR1 disarm に相当（Windows に SIGUSR1 が無いため）。

### 実装（スキャフォールド済み）
- ドライバ: [`agent/driver/windows/prevention/prevention.c`](../../agent/driver/windows/prevention/prevention.c) /
  [`prevention.h`](../../agent/driver/windows/prevention/prevention.h)
  - `PREV_STATE` に tamper 状態（enforce/disarm/protectedPid/Ob ハンドル/decision ring）。
  - `ProcessPreOp`（`OB_OPERATION_HANDLE_CREATE|DUPLICATE` の pre-op）でアクセス剥奪 + 判定キュー。
  - `RegisterTamperCallback`（DriverEntry で登録・非致命）/ `ObUnRegisterCallbacks`（Unload）。
  - IOCTL: `SET_TAMPER`（enforce+disarm）/ `PROTECT_PID`（pid+mode）/ `GET_TAMPER`（判定 pull）。
- agent: [`agent/cmd/agent/tamper_windows.go`](../../agent/cmd/agent/tamper_windows.go) +
  [`internal/platform/windows/tamper_driver_windows.go`](../../agent/internal/platform/windows/tamper_driver_windows.go)（`TamperClient`）。
  Linux の `tamper_linux.go` と同型。`windows && prevention` タグゲート（既定ビルド非影響）。

### 実機検証手順（テスト署名で可能）
1. ドライバを W4 込みで再ビルド（`prevention.sys`）→ テスト署名 → `sc start`（PoC 手順 §2〜§4）。
2. prevention タグ付き agent をビルドし `EDR_TAMPER_ENFORCE=1` で起動（保護 PID 登録 + enforce）。
3. 別シェルから `taskkill /F /PID <agentPID>` を試みる → **「アクセスが拒否されました」**で失敗、
   agent ログに `[tamper] ... 拒否（kill/inject 権限を剥奪）`。`EDR_TAMPER_ENFORCE` 無し（audit）なら
   kill は成功し、検知ログ（enforced=0）のみ ＝ **W4a 実機実証**。
4. 解除確認: `sc stop KizashiPrevention` 後は kill が通る。

### 既知の制約
- ドライバ自身・サービス停止は admin なら可能（W4a はあくまで agent プロセス保護）。
  ドライバ/サービス自体の保護・ブート時保護は W4b（PPL/ELAM）の領分。
- `ObRegisterCallbacks` は署名済みドライバを要求（テストモードではテスト署名で可）。本番は W5。

---

## W4b: PPL + ELAM（本番ハードニング・MS 証明書依存）

W4a は「他プロセス→agent の kill」を防ぐが、**agent/ドライバ自体をサービスとして止める / ブート前に
無力化する**攻撃は防げない。これを塞ぐのが PPL + ELAM。**いずれも MS 発行の特別証明書が必須**で
テスト署名では実機動作しないため、ここでは設計と手順のみ。

### PPL（Protected Process Light）
- agent サービスを **PPL（PsProtectedSignerAntimalware-Light）**として起動 → 非 PPL プロセス
  （管理者含む）からの `OpenProcess(PROCESS_TERMINATE)` 等が OS レベルで拒否される。W4a を
  OS 標準機構で裏打ちする形。
- **要件**: agent 実行ファイルを **anti-malware EKU（`1.3.6.1.4.1.311.61.4.1`）を含む証明書**で署名。
  この EKU 証明書は **Microsoft が anti-malware ベンダーにのみ発行**（Microsoft Partner Center の
  申請が必要）。自己署名/EV では不可。
- 設定: サービスの `LaunchProtected`（`SERVICE_LAUNCH_PROTECTED_ANTIMALWARE_LIGHT`）を
  `ChangeServiceConfig2` で設定。

### ELAM（Early Launch Anti-Malware）
- **ELAM ドライバ**をブート初期（他のブートドライバより前）にロードし、後続ドライバ/サービスの
  署名を検証・分類。これにより agent サービスの PPL 起動を OS が許可する土台になる。
- **要件**: ELAM ドライバを **ELAM 証明書（Microsoft 発行）**で署名し、`Wdk-AddElamCertificate` /
  リソースに ELAM 証明書情報を埋め込む。テスト署名では ELAM として登録されない。
- ELAM ドライバ自体はリソース（`MicrosoftElamCertificateInfo`）に measured boot 用の情報を持つ。

### 移行段階
1. W4a（Ob コールバック）で agent プロセス保護を提供（現状到達点・テスト署名で動作）。
2. anti-malware EKU 証明書を取得（Partner Center 申請）→ PPL 化。
3. ELAM 証明書取得 → ELAM ドライバ追加 → ブート時保護。

---

## W5: 本番署名（EV + WHQL / Attestation）

テスト署名（`testsigning on`）は検証専用。**本番エンドポイントでは無効**で、ドライバは以下が必須。

### ドライバ署名（カーネル）
- **EV コード署名証明書**を取得（DigiCert 等。ハードウェアトークン必須、組織実在検証あり）。
- **Microsoft Partner Center（Hardware Dev Center）**にアカウント作成、EV 証明書で初回登録。
- ドライバを **Attestation 署名**（簡易・対象 OS 限定）または **WHQL（HLK テスト通過）**で
  Microsoft に提出し、**Microsoft の相互署名**を得る → SecureBoot 環境でもロード可能。
- CI 反映: 署名済み `.sys` を配布パイプライン（`downloads/` 配信、Linux eBPF の `agent-ebpf.yml`
  と同様の手動 dispatch ワークフロー）に載せる。

### ユーザーランド agent 署名
- 通常の **EV/OV コード署名**で agent 実行ファイルを署名（SmartScreen 評価のため EV 推奨）。
- PPL 化する場合は W4b の anti-malware EKU 証明書が別途必要。

### 段階
1. 検証: テスト署名 + `testsigning on`（現状）。
2. 限定配布: Attestation 署名（対象 OS を絞れる・WHQL 不要）。
3. 本番: WHQL（HLK）通過 + Partner Center 署名。

---

## 関連
- W0〜W3: [../Windowsカーネル防御PoC手順.md](../Windowsカーネル防御PoC手順.md)
- 全体設計: [Windows・macOS実行前防御と改ざん防止設計.md](Windows・macOS実行前防御と改ざん防止設計.md)
- Linux 版（実証済み・同型思想）: [Linux改ざん防止と実行前防御設計.md](Linux改ざん防止と実行前防御設計.md)
