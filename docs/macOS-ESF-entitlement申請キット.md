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

```
Company: <Your Company Name> (Apple Team ID: <TEAMID>)
Product: Kizashi — endpoint detection & response agent for enterprise/SMB customers.
Distribution: Signed with our Developer ID Application certificate, notarized, and deployed to
managed enterprise endpoints via MDM (not the Mac App Store).

Why we need the Endpoint Security entitlement:
Our macOS agent provides security monitoring and active protection equivalent to commercial
EDR products. We require the Endpoint Security Framework to:

1. Observe security-relevant events in real time: process executions (ES_EVENT_TYPE_NOTIFY_EXEC),
   file events, and related telemetry, to detect malicious activity on managed endpoints.

2. Perform pre-execution prevention using AUTHORIZATION events
   (ES_EVENT_TYPE_AUTH_EXEC): when an administrator has defined a deny rule for a known-malicious
   binary, the agent must authorize or deny the execution synchronously
   (es_respond_auth_result with ES_AUTH_RESULT_DENY) before the process runs. This is the macOS
   counterpart to the kernel-level prevention we already ship on Linux (eBPF LSM).

The agent runs as a System Extension, is administered centrally, and prevention is opt-in and
fail-open by default (audit-only until an administrator explicitly enables enforcement). We do not
collect end-user content; only security metadata is processed. This entitlement is essential because
there is no other supported macOS API to authorize/deny process execution from user space.
```

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

1. **ESF を AUTH に拡張**: 既存 `agent/internal/platform/darwin/process_collector_esf.go`（`darwin && esf` タグ、
   現状 NOTIFY 観測スタブ）を `ES_EVENT_TYPE_AUTH_EXEC` 購読＋`es_respond_auth_result` に拡張。
   ルール源は共通の `process_block_rules`（`action=alert`→ALLOW+記録 / `block`→DENY）。fail-open＝
   AUTH タイムアウトは ALLOW。
2. **System Extension 化 + 署名 + 公証 + staple**（plist コメントの手順）:
   ```
   codesign --entitlements agent/deploy/darwin/entitlements.plist \
     --sign "Developer ID Application: <Company> (<TEAMID>)" --options runtime --timestamp <bundle>
   xcrun notarytool submit <zip> --apple-id <id> --team-id <TEAMID> --password @keychain:AC_PASSWORD --wait
   xcrun stapler staple <bundle>
   ```
3. **MDM 配布プロファイル**で System Extension とフルディスクアクセス（TCC）を事前承認（ユーザー手動承認の摩擦回避）。
4. **CGO + macOS ビルドホスト必須**（ESF は C API、クロスコンパイル不可）。`make build-darwin-esf` 経路を整備。
5. audit で誤検知実測 → per-endpoint で enforce 昇格（Linux と同じ段階思想）。

---

## 5. 提出チェックリスト

- [ ] Apple Developer Program（組織）メンバーシップ有効
- [ ] Team ID 確認
- [ ] §2 の justification を自社情報に差し替え
- [ ] §1 フォームから Endpoint Security entitlement を申請
- [ ] 承認連絡を待つ（数週間）。並行して Windows ドライバ PoC を進めてよい
- [ ] 承認後 → §4（ESF AUTH 実装・署名・公証・MDM 配布）

> 申請の提出自体（Apple フォーム送信）と承認は **Apple Developer アカウント保有者の作業**。本キットは
> その提出を即可能にするための文面・手順・entitlements を揃えたもの。
