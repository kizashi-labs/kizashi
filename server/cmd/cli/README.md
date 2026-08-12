# edr-cli — Kizashi CLI

## ビルド方法

```bash
# cobra依存関係を追加（初回のみ）
cd server
go get github.com/spf13/cobra@latest

# ビルド
go build -o edr-cli ./cmd/cli/

# 全プラットフォーム向けビルド
GOOS=linux   GOARCH=amd64 go build -o dist/edr-cli-linux-amd64   ./cmd/cli/
GOOS=windows GOARCH=amd64 go build -o dist/edr-cli-windows-amd64.exe ./cmd/cli/
GOOS=darwin  GOARCH=amd64 go build -o dist/edr-cli-darwin-amd64  ./cmd/cli/
GOOS=darwin  GOARCH=arm64 go build -o dist/edr-cli-darwin-arm64  ./cmd/cli/
```

## 使用方法

```bash
# 環境変数で設定
export EDR_SERVER_URL=https://edr.example.com
export EDR_TOKEN=your-jwt-token

# または --server / --token フラグで指定
edr-cli --server https://edr.example.com --token <token> status

# エージェント管理
edr-cli agents list
edr-cli agents list --status online
edr-cli agents isolate <agent-id>
edr-cli agents unisolate <agent-id>

# アラート管理
edr-cli alerts list --severity critical
edr-cli alerts list --status open --limit 100
edr-cli alerts resolve <alert-id>
edr-cli alerts false-positive <alert-id>
edr-cli alerts export --output csv > alerts.csv

# 検知ルール管理
edr-cli rules list
edr-cli rules enable <rule-id>
edr-cli rules disable <rule-id>
edr-cli rules export --format sigma > rules.yml
edr-cli rules import rules.yml

# ユーザー管理
edr-cli users list
edr-cli users invite analyst@example.com --role analyst
edr-cli users set-role <user-id> admin
edr-cli users deactivate <user-id>

# バックアップ
edr-cli backup create
edr-cli backup list
edr-cli backup restore <backup-id>

# システム状態
edr-cli status

# 出力フォーマット変更
edr-cli alerts list -o json
edr-cli agents list -o csv
```
