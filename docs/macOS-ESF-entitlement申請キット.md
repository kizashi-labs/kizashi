# macOS Endpoint Security（ESF）Entitlement 申請キット

**目的**: macOS で**実行前防御（exec の AUTH 拒否）・改ざん防止**を実装する前提となる Apple の
Endpoint Security entitlement（`com.apple.developer.endpoint-security.client`）を取得するための、
**今すぐ提出できる申請一式**。承認は数週間かかる律速のため、コードより先に提出する。

関連設計: [design/Windows・macOS実行前防御と改ざん防止設計.md](design/Windows・macOS実行前防御と改ざん防止設計.md)（§3 macOS / §5 M0-M1）

---

## 0. 前提（申請前に揃えるもの）

- **Apple Developer Program（組織 / Organization）メンバーシップ**（個人アカウント不可。D-U-N-S 番号で組織登録が必要）。
- 申請は **Account Holder（または適切な権限）** で行う。
- bundle ID（既存 LaunchDaemon: `com.edrplatform.agent`）。System Extension として配布する場合は
  拡張用に `com.edrplatform.agent.esfextension` 等を別途登録（§4）。
- entitlements ファイル: `agent/deploy/darwin/entitlements.plist`（`com.apple.developer.endpoint-security.client` を含む。既存）。

> ⚠️ 承認前にこの entitlement を付けて署名しても、ESF クライアント作成は
> `ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED` で失敗する。**承認が前提**。

---

## 1. 申請フォーム

**URL**: https://developer.apple.com/contact/request/system-extension/
（「System Extension and Endpoint Security」リクエスト。Endpoint Security の項目を選択）

フォームでは概ね以下を聞かれる。下の §2 の文面を貼れるように用意済み。
- 会社情報（Team ID / 組織名）
- アプリ概要・配布方法
- なぜ Endpoint Security が必要か（ユースケース）
- 使用する ES イベント種別（特に AUTH 系を使う旨）

---

## 2. 提出用 justification（英語・コピペ可）

> Apple のフォームは英語。以下をそのまま貼り、固有名詞（Team ID / 会社名 / 配布 MDM 名）だけ差し替える。

> ⚠️ **この文面は署名する実体と一致していなければならない。** 申請は「何をするか」を Apple に
> 申告する文書で、承認後に署名するバイナリの挙動と食い違えば、審査で弾かれるか、後で
> 説明を求められる。下の文面は 2026-08-10 に**実装と突合して修正済み**（§6 に対応表）。
> 実装を変えたら、ここも直すこと。

```
Company: <Your Company Name> (Apple Team ID: <TEAMID>)
Product: Kizashi — endpoint detection & response agent for enterprise/SMB customers.
Distribution: Signed with our Developer ID Application certificate, notarized, and deployed to
managed enterprise endpoints via MDM (not the Mac App Store).

Why we need the Endpoint Security entitlement:
Our macOS agent provides security monitoring and active protection equivalent to commercial
EDR products. We require the Endpoint Security Framework to:

1. Observe process lifecycle events in real time — ES_EVENT_TYPE_NOTIFY_EXEC and
   ES_EVENT_TYPE_NOTIFY_EXIT — to build the process tree and detect malicious execution
   chains on managed endpoints. (Our file and network telemetry comes from other macOS
   APIs; we are not requesting ES file events at this time.)

2. Perform pre-execution prevention using AUTHORIZATION events —
   ES_EVENT_TYPE_AUTH_EXEC: when an administrator has defined a deny rule for a
   known-malicious binary, the agent must authorize or deny the execution synchronously
   (es_respond_auth_result with ES_AUTH_RESULT_DENY) before the process runs. This is the
   macOS counterpart to the kernel-level prevention we already ship on Linux (eBPF LSM,
   bprm_check_security).

The agent runs as a root LaunchDaemon (com.edrplatform.agent), is administered centrally, and
prevention is opt-in and fail-open by default: the enforcement switch is off unless an
administrator explicitly enables it, and any AUTH event we cannot decide is allowed. We do not
collect end-user content; only security metadata is processed. This entitlement is essential
because there is no other supported macOS API to authorize or deny process execution.
```

> **LaunchDaemon か System Extension か。** 現在の実装は root LaunchDaemon で、上の文面も
> そう書いてある。System Extension として配布する場合は entitlements.plist の
> `com.apple.developer.system-extension.install`（現在コメントアウト）を有効化し、
> **この文面も併せて直す必要がある**。どちらも ESF クライアントとして有効な形態なので、
> 申請時点の実体に合わせるのが正しい。

---

## 3. entitlements（申請に紐づく付与内容）

実体は `agent/deploy/darwin/entitlements.plist`。中核キー:

| キー | 値 | 用途 |
|---|---|---|
| `com.apple.developer.endpoint-security.client` | true | ESF クライアント（**要 Apple 承認**） |
| `com.apple.security.network.client` | true | EDR サーバへの gRPC |
| Hardened Runtime 各種 | — | 署名整合性 |

System Extension として配布する場合は `com.apple.developer.system-extension.install`（コメントアウト中）を有効化。

---

## 4. 承認後の手順（M1 実装フェーズ）

> 2026-08-10 時点の実態に更新。**1 と 4 は実装済み**で、承認待ちなのは署名と配布だけ。

1. ~~**ESF を AUTH に拡張**~~ — ✅ **実装済み**。`agent/internal/platform/darwin/prevention_esf.go`
   が `ES_EVENT_TYPE_AUTH_EXEC` を購読し `es_respond_auth_result` で応答する。ルール源は共通の
   `process_block_rules`（`action=alert`→ALLOW+記録 / `block`→DENY）、fail-open が既定。
   NOTIFY 側（EXEC/EXIT）は `process_collector_esf.go`。
2. **署名 + 公証 + staple** — ワークフロー `.github/workflows/agent-macos-esf.yml` に実装済みで、
   Apple のシークレットを設定すれば動く。**未署名のものは `downloads/` に公開しない**設計
   （未署名 ESF は `es_new_client` が `ERR_NOT_ENTITLED` で失敗し、既定ビルドより明確に劣るため）。
   必要なシークレット: `APPLE_DEVELOPER_ID_P12` / `APPLE_DEVELOPER_ID_P12_PASSWORD` /
   `APPLE_SIGN_IDENTITY` / `APPLE_INSTALLER_IDENTITY` / `APPLE_TEAM_ID` /
   `APPLE_NOTARY_APPLE_ID` / `APPLE_NOTARY_APP_PASSWORD`。
   > **pkg 署名は "Developer ID Installer" 証明書**。バイナリ用の "Developer ID Application" と
   > 別物で、取り違えるとビルドマシンでは入るのに他の全ての Mac で拒否される pkg ができる。
3. **MDM 配布プロファイル**でフルディスクアクセス（TCC）を事前承認（ユーザー手動承認の摩擦回避）。
   System Extension として配布する場合はその事前承認も併せて。
4. ~~**CGO + macOS ビルドホスト必須**~~ — ✅ **経路整備済み**。`make build-darwin-esf` に加え、
   `agent-macos-esf.yml` が macOS ランナーで `CGO_ENABLED=1` のネイティブビルドを回す。
   なお `-tags esf` + `CGO_ENABLED=0` は**ポーリング実装へ安全に縮退**する（cgo ビルドタグで
   保証済み）ので、承認前でも既定の darwin ビルドは一切影響を受けない。
5. audit で誤検知実測 → per-endpoint で enforce 昇格（Linux と同じ段階思想）。

---

## 5. 提出チェックリスト

- [ ] Apple Developer Program（組織）メンバーシップ有効
- [ ] Team ID 確認
- [ ] §2 の justification を自社情報に差し替え（`<Your Company Name>` / `<TEAMID>`）
- [ ] **§6 の対応表を確認** — 実装を変えていれば §2 の文面も直す
- [ ] §1 フォームから Endpoint Security entitlement を申請
- [ ] 承認連絡を待つ（数週間）
- [ ] 承認後 → §4-2（署名シークレットを設定して `agent-macos-esf.yml` を実行）

> 申請の提出自体（Apple フォーム送信）と承認は **Apple Developer アカウント保有者の作業**。本キットは
> その提出を即可能にするための文面・手順・entitlements を揃えたもの。

---

## 6. 申請文面と実装の対応（2026-08-10 突合）

申請は Apple への申告なので、**署名する実体と一致していること**が要件になる。
§2 の各主張がどのコードに対応するかを明示しておく。実装を変えたらここと §2 を直すこと。

| §2 の主張 | 実装 | 確認方法 |
|---|---|---|
| `ES_EVENT_TYPE_NOTIFY_EXEC` / `NOTIFY_EXIT` を購読 | `internal/platform/darwin/process_collector_esf.go` の `es_subscribe` | `grep ES_EVENT_TYPE_ internal/platform/darwin/*.go` |
| `ES_EVENT_TYPE_AUTH_EXEC` ＋ `es_respond_auth_result` | `internal/platform/darwin/prevention_esf.go`（`esf && prevention && cgo`） | 同上 |
| ES の file events は**要求しない** | darwin の file collector は `file_collector.go`（`//go:build darwin`、ESF 非経由） | ファイル冒頭のビルドタグ |
| root **LaunchDaemon** として動作（System Extension ではない） | `agent/deploy/darwin/com.edrplatform.agent.plist`（`UserName` = `root`、`/Library/LaunchDaemons/` へ配置） | plist の `UserName` |
| prevention は既定 off・fail-open | `EDR_PREVENTION_ENFORCE=1` の時のみ enforce。ES クライアント作成失敗時は observe 継続 | `cmd/agent/prevention_darwin.go:39` |
| Developer ID 署名 + 公証 + MDM 配布（App Store 外） | `.github/workflows/agent-macos-esf.yml` の codesign / notarytool ステップ | 同ワークフロー |

### 修正履歴

**2026-08-10**: §2 の文面に実装と食い違う記述が2件あったため修正した。

1. **「System Extension として動作する」→ 実際は LaunchDaemon。** System Extension 化は
   されておらず、`com.apple.developer.system-extension.install` もコメントアウトのまま。
   どちらも ESF クライアントとして有効な形態だが、申告と実体が違うのは避けるべき。
2. **「ESF で file events を観測する」→ ESF が扱うのは EXEC / EXIT のみ。**
   ファイル監視は別 API 経由。要求しない権限を申請文面に書くと、審査で説明を求められる。

この種の乖離（ドキュメントの主張 ≠ 実装）は本リポジトリで繰り返し起きているので、
§6 の対応表を置いて追跡可能にした。

> なお `.pkg` としての配布（`packaging/macos/`）は別PRで追加している。上の表は本ブランチに
> 存在するファイルのみを参照しているので、`.pkg` 側がマージされたら
> `packaging/macos/com.edrplatform.agent.plist` も LaunchDaemon の根拠として追記してよい
> （両者とも root LaunchDaemon で、申告内容は変わらない）。
