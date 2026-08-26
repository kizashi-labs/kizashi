# エンドポイント可視性 実機検証スクリプト

インストール済み EDR-Agent が稼働するエンドポイントで、テレメトリ収集が
実際に機能しているかを実機検証するためのスクリプト群。
[`docs/ETW検証ランブック.md`](../../docs/ETW検証ランブック.md) の手順を、実運用中の
エンドポイント向けにまとめたもの。

## ファイル

| ファイル | 対象 | 内容 |
|---------|------|------|
| `verify-windows.ps1` | Windows | サービス状態 + ログから収集経路(ETW/ポーリング)判定 + `etw-verify.exe` 実行 |
| `verify-linux.sh` | Linux | サービス状態 + ログ確認 + eBPF状態 + 既知活動(marker)生成 |
| `etw-verify.exe` | Windows | opt-in ETW コレクタの PASS/FAIL ハーネス(`cmd/etw-verify`、gitignore対象) |

## 使い方

### Windows エンドポイント

1. `etw-verify.exe` を生成（開発機、どのOSでも可）:
   ```
   cd agent && GOOS=windows GOARCH=amd64 go build -o scripts/etw-verify.exe ./cmd/etw-verify
   ```
2. `verify-windows.ps1` と `etw-verify.exe` を**同じフォルダ**に置いて対象 Windows へ転送。
3. **管理者として実行**した PowerShell から:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\verify-windows.ps1
   ```
4. 出力（セクション0〜3）をそのまま貼り戻す。

判定:
- `[PASS] process/network/dns` … その経路が実機でリアルタイムにイベントを出す（= 可視性検証済み）
- ログに「ETW…を開始しました」… エージェント本体も ETW 経路で稼働中
- ログに「ポーリングにフォールバックします」… 既定のポーリング経路（`EDR_AGENT_ETW` 未設定 or 非管理者）

### Linux エンドポイント

1. `verify-linux.sh` を対象 Linux へ転送。
2. root で実行:
   ```bash
   sudo bash verify-linux.sh
   ```
3. 出力（セクション0〜4）と、EDR サーバコンソールで marker（`edrverify_*` プロセス /
   `edrverify-*.example.com` DNS / `1.1.1.1:443` 接続）が見えたかを貼り戻す。

> 注意: 出荷ビルド（`ebpf` タグ無し）の Linux プロセス監視は `/proc` ポーリングです
> （eBPF 経路はビルド未完成のため未稼働）。Linux 検証は「ポーリング経路が動いて
> サーバへ転送しているか」の確認が主目的になります。

## エージェントで ETW を恒久有効化する（検証後）

検証で ETW 経路の動作を確認できたら、本番エージェントでも有効化できる:

- Windows サービス `EDRAgent` の環境変数に `EDR_AGENT_ETW=1` を追加して再起動
- 未設定時は従来のポーリング経路にフォールバック（後方互換）

詳細は [`docs/技術的負債と改善計画.md`](../../docs/技術的負債と改善計画.md) の P4 章を参照。
