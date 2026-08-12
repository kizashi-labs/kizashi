# 検知率向上 2026-07-20 — Discovery（探索）戦術の相関連動とホスト偵察バースト

## 背景（何が穴だったか）

builtin Sigma ルールを ATT&CK 技術別に数えると、**Discovery（探索）戦術がほぼ未カバー**だった：

| 技術 | 内容 | 修正前 builtin |
|---|---|---|
| T1082 | System Information Discovery (`systeminfo` / `uname`) | 0 |
| T1057 | Process Discovery (`tasklist` / `ps`) | 0 |
| T1016 | System Network Config Discovery (`ipconfig` / `ifconfig`) | 0 |
| T1049 | System Network Connections Discovery (`netstat` / `ss`) | 0 |
| T1033 | System Owner/User Discovery (`whoami`) | 0 |
| T1007 | System Service Discovery (`sc query` / `systemctl`) | 0 |
| T1069 | Permission Groups Discovery (`net localgroup`) | 0 |
| T1083 | File and Directory Discovery（広域列挙のみ） | 0 |
| T1087 / T1518 | Account / Software Discovery | 各1 |

探索コマンドは `command_line`（＝サポート済みフィールド）で素直にマッチできるが、
**単発でルール化すると誤検知の塊**になる（管理者・在庫管理エージェントが日常的に実行する）。
そのため「単純に低severityルールを足す」のは筋が悪い。

## 方針 — 単発では鳴らさず、相関に効かせる

既存の `KillChainScorer`（`killchain.go`）は「単発ではアラート未満の弱い信号を
ATT&CK **戦術**横断で集約し、1ホストが複数の kill-chain 段を跨いだら高信頼で相関検知する」
設計。ここに **探索段(discovery)** を供給するのが最も費用対効果が高い。

実装（`server/internal/detection/discovery.go`）:

1. **`classifyDiscoveryCommand(cmdline) string`** — プロセスのコマンドラインを
   探索技術ID（T1033/T1082/T1057/T1016/T1049/T1007/T1069/T1518/T1087/T1083）へ
   分類する純関数。`net localgroup`→T1069 を `net user`→T1087 より先に判定する等、
   曖昧語を避けた特異トークンで構成。`ls`/`dir`/`id`/`ver` 等の汎用形は**分類しない**。

2. **kill-chain への供給（本命）** — `engine.go` の `processEventData` で、process
   イベントのコマンドラインを分類し、認識した探索技術タグを **KillChainScorer に
   投入**する。**単発の探索コマンドは単独アラートにしない**（誤検知ゼロ）。kill-chain は
   4つの異なる戦術が揃って初めて発火するため、`whoami` 単発が何かを鳴らすことは構造上
   あり得ない。一方で、これまで「実行＋認証情報アクセス＋持ち出し」の3戦術で止まって
   相関しなかった多段侵入が、探索段の供給で4戦術に到達し**相関検知が成立する**。

3. **ホスト偵察バースト（`DiscoveryScorer`）** — 1ホストが短時間(5分)窓で
   **4種以上の異なる探索技術**を実行した場合のみ、相関アラートを1件発火（severity 5、
   6種以上で6）。単発・少数は鳴らさず、着地後のハンズオンキーボード偵察に特有の
   「広範囲を一気に叩く」挙動だけを捕捉。`KillChainScorer` と同じ実績ある構造
   （スライディング窓・ホスト別状態・初回越えで発火＋増加で段階昇格・決定的クロック）。

## なぜ誤検知が増えないか

- **kill-chain 供給**は、探索技術を単独アラート化せず戦術集約にのみ使う。発火には
  探索以外の3戦術（実行/認証情報アクセス/永続化/C2/持ち出し等）が同一ホストで
  必要なため、正常な管理操作が相関検知を誘発しない。
- **偵察バースト**は「短時間に4種以上の異なる探索技術」という特異条件。単発の
  `whoami` や `ipconfig` 2回では鳴らない。閾値・窓は `discMinTechniques` /
  `discWindow` で調整可能、FP が出れば suppression / `CurateScheduler.MonitorFP`
  で個別隔離できる。

## テスト（`discovery_test.go`）

- `TestClassifyDiscoveryCommand` — 40超のケースで技術分類と、汎用形/非探索コマンドを
  分類しないことを検証。
- `TestDiscoveryScorer_FiresOnBurst` / `_SingleCommandNoAlert` /
  `_RepeatedSameTechniqueNoBurst` / `_ExpiresOutsideWindow` — バースト発火/単発無音/
  同一技術反復無音/窓外失効。
- `TestDiscoveryCompletesKillChain` — **本命の価値の実証**：実行＋認証情報アクセス＋
  持ち出しの3戦術は相関しない（0件）が、`ipconfig` 由来の探索段を足すと4戦術に到達し
  相関アラートが**1件**発火することを決定的に検証。

## 効果

- **相関検知率の底上げ**：探索段を欠いて3戦術で止まっていた多段攻撃が4戦術で成立。
- **単発検知の誤検知ゼロ**：探索コマンド単発では一切アラートを出さない。
- **偵察バーストの可視化**：広範囲の連続探索という強いハンズオン兆候を低ノイズで1件化。

二重エンジンの配置（`docs/検知ルールの二重管理とデプロイ.md`）に整合：本機能は
**detection サーバ**（`cmd/detection` → `NewEngine`）側に置き、kill-chain と同じ経路で動く。
builtin Sigma（API サーバ側）は kill-chain に供給されないため、探索段はあえて builtin では
なく detection エンジンの typed 経路に実装している。
