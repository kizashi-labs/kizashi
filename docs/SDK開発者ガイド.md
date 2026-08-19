# Kizashi — SDK 開発者ガイド

> **対象読者**: EDR Platform の REST API を TypeScript / Python から呼び出すアプリケーション開発者・自動化エンジニア

---

## 目次

1. [概要](#1-概要)
2. [認証](#2-認証)
3. [TypeScript SDK](#3-typescript-sdk)
4. [Python SDK](#4-python-sdk)
5. [リソース一覧とメソッド](#5-リソース一覧とメソッド)
6. [エラーハンドリング](#6-エラーハンドリング)
7. [ページネーション](#7-ページネーション)
8. [実装例](#8-実装例)
9. [直接 REST API を呼び出す場合](#9-直接-rest-api-を呼び出す場合)

---

## 1. 概要

Kizashi は以下の2つの公式クライアント SDK を提供します。

| SDK | パッケージ名 | 動作環境 |
|-----|------------|---------|
| TypeScript / Node.js | `@kizashi-edr/client` | Node.js 18+, Deno, ブラウザ（バンドル後） |
| Python | `kizashi-edr-client` | Python 3.9+ |

両 SDK は**外部依存ゼロ**で設計されており、標準ライブラリの HTTP クライアントのみを使用します。

---

## 2. 認証

### JWT トークンの取得

```http
POST /api/v1/auth/login
Content-Type: application/json

{"email": "admin@example.com", "password": "Password123!"}
```

レスポンス:
```json
{"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...", "user": {...}}
```

### トークンのリフレッシュ

JWT の有効期限が切れる前にリフレッシュできます。

```http
POST /api/v1/auth/refresh
Authorization: Bearer <current-token>
```

### APIキーを使う場合

管理画面（**管理 → 統合 → APIキー**）で発行した APIキーを `Bearer` トークンとして使用できます。自動化スクリプトでは JWT よりも APIキーの使用を推奨します。

---

## 3. TypeScript SDK

### インストール

```bash
npm install @kizashi-edr/client
# または
yarn add @kizashi-edr/client
```

### 初期化

```typescript
import { KizashiEDRClient } from "@kizashi-edr/client";

const client = new KizashiEDRClient({
  baseURL: "https://edr.your-company.com",
  apiKey: process.env.EDR_API_KEY!,   // JWT または APIキー
});
```

### 型定義

SDK は以下の主要な型をエクスポートします。

```typescript
import type {
  Alert,
  AlertFilter,
  Agent,
  Incident,
  IncidentStatus,
  IncidentUpdatePayload,
  SigmaRule,
  RuleInput,
  Vulnerability,
  APIKey,
  LiveResponseSession,
  CommandResult,
  EDRError,
} from "@kizashi-edr/client";
```

---

## 4. Python SDK

### インストール

```bash
pip install kizashi-edr-client

# 開発用（テストツール含む）
pip install "kizashi-edr-client[dev]"
```

### 初期化

```python
from kizashi_edr import KizashiEDRClient

client = KizashiEDRClient(
    base_url="https://edr.your-company.com",
    api_key=os.environ["EDR_API_KEY"],  # JWT または APIキー
)
```

### SDK自体のテスト実行

両SDKとも本体リポジトリ内にテストスイートを持ち、`ci.yml` の `sdk-test` ジョブで push/PR ごとに実行される。

```bash
# TypeScript（sdk/typescript/）
npm install   # vitest を devDependency として導入
npm test      # src/client.test.ts（45件）

# Python（sdk/python/）
pip install -r requirements-dev.txt
pytest -q     # tests/test_client.py（56件）
```

---

## 5. リソース一覧とメソッド

### alerts（アラート）

| メソッド | TypeScript | Python | 説明 |
|---------|-----------|--------|------|
| 一覧取得 | `client.alerts.list(filter?)` | `client.alerts.list(...)` | フィルタ付き一覧 |
| 単件取得 | `client.alerts.get(id)` | `client.alerts.get(alert_id)` | アラート詳細 |
| 分類 | `client.alerts.classify(id, data)` | `client.alerts.classify(...)` | 単件AI分類 |
| 一括分類 | `client.alerts.bulkClassify(ids, data)` | `client.alerts.bulk_classify(...)` | 複数アラートを一括分類 |

```typescript
// TypeScript 例
const alerts = await client.alerts.list({ status: "open", severity_min: 7 });
await client.alerts.bulkClassify(["alert-1", "alert-2"], { category: "malware" });
```

```python
# Python 例
alerts = client.alerts.list(status="open", severity_min=7)
client.alerts.bulk_classify(["alert-1", "alert-2"], category="malware")
```

---

### agents（エージェント）

| メソッド | TypeScript | Python | 説明 |
|---------|-----------|--------|------|
| 一覧取得 | `client.agents.list(filter?)` | `client.agents.list(...)` | エージェント一覧 |
| 単件取得 | `client.agents.get(id)` | `client.agents.get(agent_id)` | エージェント詳細 |
| 隔離 | `client.agents.isolate(id)` | `client.agents.isolate(agent_id)` | ネットワーク隔離 |
| 隔離解除 | `client.agents.unisolate(id)` | `client.agents.unisolate(agent_id)` | 隔離解除 |

```typescript
// エージェントを隔離
await client.agents.isolate("agent-uuid");

// オフラインのエージェントを取得
const offline = await client.agents.list({ status: "offline" });
```

---

### incidents（インシデント）

| メソッド | TypeScript | Python | 説明 |
|---------|-----------|--------|------|
| 一覧取得 | `client.incidents.list(filter?)` | `client.incidents.list(...)` | インシデント一覧 |
| 単件取得 | `client.incidents.get(id)` | `client.incidents.get(incident_id)` | インシデント詳細 |
| 作成 | `client.incidents.create(data)` | `client.incidents.create(...)` | 手動インシデント作成 |
| 更新 | `client.incidents.update(id, data)` | `client.incidents.update(id, ...)` | ステータス・担当者更新 |

```typescript
// インシデントを調査中に更新し、担当者を割り当て
await client.incidents.update("INC-001", {
  status: "investigating",
  assigned_to: "analyst@example.com",
  description: "ランサムウェアの疑い。P1対応を開始。",
});
```

```python
# Python 例（Noneを渡したフィールドはリクエストから省略される）
client.incidents.update(
    "INC-001",
    status="investigating",
    assigned_to="analyst@example.com",
)
```

---

### rules（検知ルール）

| メソッド | TypeScript | Python | 説明 |
|---------|-----------|--------|------|
| 一覧取得 | `client.rules.list(filter?)` | `client.rules.list(...)` | ルール一覧 |
| 作成 | `client.rules.create(data)` | `client.rules.create(...)` | ルール作成 |
| 単件取得 | `client.rules.get(id)` | `client.rules.get(rule_id)` | ルール詳細 |
| 更新 | `client.rules.update(id, data)` | `client.rules.update(id, ...)` | ルール更新（部分更新） |
| 削除 | `client.rules.delete(id)` | `client.rules.delete(rule_id)` | ルール削除 |

```typescript
// ルールを無効化
await client.rules.update("rule-uuid", { enabled: false });

// ルールを削除
await client.rules.delete("rule-uuid");
```

```python
# 特定ルールの詳細取得と無効化
rule = client.rules.get("rule-uuid")
print(rule["name"], rule["severity"])
client.rules.update("rule-uuid", enabled=False)
```

---

### vulnerabilities（脆弱性）

| メソッド | TypeScript | Python | 説明 |
|---------|-----------|--------|------|
| 一覧取得 | `client.vulnerabilities.list(filter?)` | `client.vulnerabilities.list(...)` | 脆弱性一覧 |
| 単件取得 | `client.vulnerabilities.get(id)` | `client.vulnerabilities.get(vuln_id)` | 脆弱性詳細 |
| 統計 | `client.vulnerabilities.stats()` | `client.vulnerabilities.stats()` | CVSSスコア分布等 |

```typescript
// CVSS 7.0 以上の未修正脆弱性一覧
const vulns = await client.vulnerabilities.list({
  cvss_min: 7.0,
  status: "open",
});
```

---

### apiKeys（APIキー管理）

| メソッド | TypeScript | Python | 説明 |
|---------|-----------|--------|------|
| 一覧取得 | `client.apiKeys.list()` | `client.api_keys.list()` | APIキー一覧 |
| 作成 | `client.apiKeys.create(data)` | `client.api_keys.create(name, ...)` | 新規APIキー発行 |
| 失効 | `client.apiKeys.revoke(id)` | `client.api_keys.revoke(key_id)` | APIキー失効 |

```typescript
// CI/CD パイプライン用キーを発行（90日有効）
const key = await client.apiKeys.create({
  name: "github-actions",
  scopes: ["read", "write"],
  expires_at: new Date(Date.now() + 90 * 86400_000).toISOString(),
});
console.log("Save this key:", key.raw_key); // 一度だけ表示
```

---

### liveResponse（ライブレスポンス）

| メソッド | TypeScript | Python | 説明 |
|---------|-----------|--------|------|
| 一覧取得 | `client.liveResponse.list()` | `client.live_response.list()` | セッション一覧 |
| セッション開始 | `client.liveResponse.open(agentId)` | `client.live_response.open(agent_id)` | リモートセッション開始 |
| コマンド実行 | `client.liveResponse.exec(sessionId, cmd)` | `client.live_response.exec(session_id, command)` | コマンド送信 |

```typescript
// エージェントにリモート接続してコマンドを実行
const session = await client.liveResponse.open("agent-uuid");
const result = await client.liveResponse.exec(session.id, "ps aux | grep suspicious");
console.log(result.output);
```

---

## 6. エラーハンドリング

両 SDK は HTTP エラーを `EDRError` 例外としてスローします。

### TypeScript

```typescript
import { KizashiEDRClient, EDRError } from "@kizashi-edr/client";

try {
  await client.agents.isolate("unknown-agent-id");
} catch (err) {
  if (err instanceof EDRError) {
    console.error(`HTTP ${err.status}: ${err.message}`);
    // err.status: 404, 401, 403, 429, 500 等
  }
}
```

### Python

```python
from kizashi_edr import KizashiEDRClient, EDRError

try:
    client.agents.isolate("unknown-agent-id")
except EDRError as e:
    print(f"HTTP {e.status_code}: {e}")
    if e.status_code == 429:
        print("レート制限。しばらく待ってから再試行してください。")
```

### 主なエラーコード

| ステータス | 意味 | 対処 |
|-----------|------|------|
| 400 | リクエスト不正 | パラメータを確認 |
| 401 | 認証エラー | トークンを再取得 |
| 403 | 権限不足 | スコープを確認 |
| 404 | リソース不存在 | IDを確認 |
| 429 | レート制限超過 | 間隔を空けて再試行 |
| 500 | サーバーエラー | サーバーログを確認 |

---

## 7. ページネーション

一覧系メソッドはすべてページネーションをサポートします。

### TypeScript

```typescript
// 全アラートを取得（自動ページング）
let offset = 0;
const limit = 50;
const allAlerts = [];

while (true) {
  const page = await client.alerts.list({ limit, offset });
  allAlerts.push(...page.data);
  if (allAlerts.length >= page.total) break;
  offset += limit;
}
```

### Python

```python
# ジェネレータパターン
def iter_alerts(client, **filters):
    offset = 0
    limit = 50
    while True:
        page = client.alerts.list(limit=limit, offset=offset, **filters)
        yield from page["data"]
        offset += limit
        if offset >= page["total"]:
            break

for alert in iter_alerts(client, status="open"):
    print(alert["id"], alert["severity"])
```

---

## 8. 実装例

### インシデント自動クローズスクリプト

解決済みアラートのみを含むインシデントを自動クローズします。

```python
from kizashi_edr import KizashiEDRClient

client = KizashiEDRClient(
    base_url="https://edr.your-company.com",
    api_key=os.environ["EDR_API_KEY"],
)

incidents = client.incidents.list(status="open")
for inc in incidents["data"]:
    detail = client.incidents.get(inc["id"])
    all_resolved = all(
        a["status"] == "resolved" for a in detail.get("alerts", [])
    )
    if all_resolved:
        client.incidents.update(inc["id"], status="closed")
        print(f"Closed: {inc['id']}")
```

### 高リスク脆弱性 Slack 通知

```typescript
import { KizashiEDRClient } from "@kizashi-edr/client";

const client = new KizashiEDRClient({
  baseURL: process.env.EDR_BASE_URL!,
  apiKey: process.env.EDR_API_KEY!,
});

const vulns = await client.vulnerabilities.list({ cvss_min: 9.0, status: "open" });

if (vulns.data.length > 0) {
  await fetch(process.env.SLACK_WEBHOOK_URL!, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      text: `🚨 CVSS 9.0以上の未修正脆弱性が ${vulns.data.length} 件あります`,
    }),
  });
}
```

### 古いAPIキーの自動失効（90日以上）

```python
from datetime import datetime, timezone, timedelta

keys = client.api_keys.list()
threshold = datetime.now(timezone.utc) - timedelta(days=90)

for key in keys["api_keys"]:
    if key.get("expires_at"):
        expires = datetime.fromisoformat(key["expires_at"])
        if expires < threshold:
            client.api_keys.revoke(key["id"])
            print(f"Revoked expired key: {key['name']}")
```

---

## 9. 直接 REST API を呼び出す場合

SDK を使わずに直接 REST API を呼び出す場合は、OpenAPI 仕様を参照してください。

- **OpenAPI 仕様**: [`docs/openapi.yaml`](openapi.yaml)（113パス・164操作・全 operationId 付き）
- **Swagger UI**: サーバー起動中に `http://localhost:8080/swagger/` からブラウザで確認可能

### curl 例

```bash
# ログイン
TOKEN=$(curl -s -X POST https://edr.example.com/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"Password123!"}' \
  | jq -r .token)

# アラート一覧（open のみ、重大度7以上）
curl -s "https://edr.example.com/api/v1/alerts?status=open&severity_min=7" \
  -H "Authorization: Bearer $TOKEN" | jq .

# インシデント更新
curl -s -X PATCH "https://edr.example.com/api/v1/incidents/INC-001" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"status":"investigating","assigned_to":"analyst@example.com"}' | jq .
```

---

## 関連ドキュメント

| ドキュメント | 場所 |
|------------|------|
| OpenAPI 仕様 | [`docs/openapi.yaml`](openapi.yaml) |
| SDK ソースコード | [`sdk/README.md`](../sdk/README.md) |
| サーバーインストール手順 | [`docs/server-installation.md`](server-installation.md) |
| ユーザーガイド | [`docs/user-guide.md`](user-guide.md) |
| APIキー管理（UI） | ユーザーガイド §11 参照 |
