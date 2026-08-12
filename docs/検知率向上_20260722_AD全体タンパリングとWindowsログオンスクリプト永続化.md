# 検知率向上サマリ 2026-07-22 — AD/ドメイン全体タンパリングとWindowsログオンスクリプト永続化

監査ドキュメントの戦術別カバレッジ・マトリクスから、真に未実装の高価値ギャップ（T1484 GPOタンパリング・
T1037 Windowsログオンスクリプト・T1556 認証プロセス改変）を洗い出し、優先順に4ルールを実装した記録。
あわせて、監査ドキュメント自体の**記載漏れ（実装済みなのに「穴」と表示され続けていた項目）**を是正した。

---

## 1. 新規実装ルール（`sigma_builtins.go`）

| ルール | 技術 | 検知条件 | レベル |
|---|---|---|---|
| Domain Policy Modification via GPO Tampering | **T1484.001**（新規被覆） | `New-GPO`/`Set-GPRegistryValue`/`Set-GPPrefRegistryValue`/`SharpGPOAbuse` | high |
| Windows Logon Script Persistence via Registry | **T1037.001**（新規被覆） | `UserInitMprLogonScript` レジストリ値の設定 | high |
| Network Logon Script Deployment via NETLOGON or SYSVOL Share | **T1037.003**（新規被覆） | NETLOGON/SYSVOLへのスクリプトコピー | high |
| Domain Controller Authentication Tampering (DCShadow/AdminSDHolder Abuse) | **T1556.001**（新規被覆） | `lsadump::dcshadow`+`/pushmode`、または`dsacls`によるAdminSDHolder ACL改変 | critical |

### なぜこの4件か
- **T1484 GPOタンパリング**: GPOは**OU全体**（多数のホスト）に悪性設定（スケジュールタスク・レジストリ値・
  スクリプト）を単一操作で配布できる、ドメイン管理者権限奪取後の典型的な水平展開・永続化手口。個々のホスト
  ではなく「配布メカニズムそのもの」を検知することで、配布後に各ホストで発火する個別ルールより早い段階で
  介入できる。
- **T1037.001/.003 ログオンスクリプト**: `.001`（レジストリ値）は単一ホスト永続化、`.003`
  （NETLOGON/SYSVOL配置）は**ドメイン内の全ユーザ/OUへの一括永続化**。前者は低コストで見落とされやすく、
  後者はGPOと並ぶ「1回の書込みで広範囲に効く」永続化手口。
- **T1556.001 DCShadow/AdminSDHolder**: 単発の資格情報窃取ではなく、**Domain Admin権限への永続的かつ
  検知回避的な裏口**。DCShadowはロークDCを偽装してAD複製に不正な変更を直接注入するため、通常のイベント
  ログ監視を経由しない高度な手口であり、コマンドラインでの検知が事実上唯一の現実的な捕捉ポイント。

### テスト（`builtin_ad_persist_fire_test.go`）
発火8ケース（GPOタンパリング3種＋ログオンスクリプト2種＋DCShadow/AdminSDHolder2種）＋良性否定5ケース
（`Get-GPOReport`読取専用／無関係レジストリ値／ローカルファイルコピー／`privilege::debug`単体／無関係
オブジェクトへの`dsacls`クエリ）。

---

## 2. 監査ドキュメントの記載漏れ是正（メンテナンス上の教訓）

作業の過程で、`ATT&CK検知カバレッジ監査.md` の「🔴穴」リストに**既に実装済みのルールが記載され続けていた**
ことが判明した。実装バッチ完了時に監査ドキュメントの該当行を更新し忘れる、というこれまでも繰り返し発生
していたパターン（2026-07-09/07-10 の複数エントリでも同様の指摘あり）。

### 是正した項目
| 技術 | 実際の状態 | 実装済みルール |
|---|---|---|
| T1134（アクセストークン操作） | ✅実装済み（「最大の穴」と誤記） | Access Token Manipulation tooling検知 |
| T1197（BITSジョブ） | ✅実装済み | bitsadmin/Start-BitsTransfer |
| T1546.008（スティッキーキー） | ✅実装済み | アクセシビリティバイナリ乗っ取り |
| T1546.015（COMハイジャック） | ✅実装済み | COM Object Hijacking via Suspicious Server Path |
| T1546.010（AppInit、旧誤記T1546.001） | ✅実装済み | AppInit DLL Persistence |
| T1547.006（Linuxカーネルモジュール） | ✅実装済み | insmod/modprobe不審パス |
| T1003.004/.005（LSAシークレット/キャッシュ資格） | ✅実装済み | `TestDefenseEvasionCredFire`収載 |
| T1552.004/.006（秘密鍵/GPP cpassword） | ✅実装済み | 同上 |
| T1557.001（Responder/Inveigh） | ✅実装済み | 同上 |
| T1539（セッションCookie窃取） | ✅実装済み | ブラウザCookie DB アクセス検知 |

### 教訓・再発防止
この種の記載漏れは、**実装漏れ（検知ギャップ）とは真逆の問題**である — 実際にはカバーされているのに
「未対応」と表示され続けると、次回の優先順位付けで重複調査・重複実装の時間を浪費する。今回、候補選定の
初期段階で `grep -n "attack\.t<technique>"` によるコードベース側の一次ソース確認を徹底したことで、
4件の重複実装を未然に回避できた。**監査ドキュメントの「🔴穴」リストは実装バッチのたびに `grep` で
再検証してから次のバッチを選定する**ことを標準運用とする（`docs/ATT&CK検知カバレッジ監査.md` の
「再現コマンド」セクション参照）。

---

## テスト・検証

- サーバ: `go build ./...` / `go vet ./...` / `go test ./...` すべてグリーン
  （geoipパッケージの既知の無関係な事前障害を除く）。
- 新規テスト: `builtin_ad_persist_fire_test.go`（発火8＋否定5）。
- 既存の `TestBuiltinSigmaNoMalformedPatterns`・`TestBuiltinSigmaPrimaryTechnique` 回帰ガードも通過。

## 関連

- 監査ドキュメント: [ATT&CK検知カバレッジ監査.md](ATT&CK検知カバレッジ監査.md) §5 Persistence / §6 Privilege
  Escalation / §8 Credential Access、更新ログ 2026-07-22。
- PR: #447（検知率向上シリーズの一括PR）。
