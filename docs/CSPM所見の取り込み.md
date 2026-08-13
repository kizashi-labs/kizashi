# CSPM 所見の取り込み

`/cloud-security`（クラウドセキュリティ態勢）に表示するデータを入れる手順。

## 前提: このリポジトリに CSPM スキャナは無い

クラウドへ接続して設定を検査する処理は実装されていません。`POST /api/v1/cloud/scan` は **501 Not Implemented** を返します（以前は何もしないのに 200 と「スキャン完了」を返していました。詳細は PR #679）。

代わりに、**既存の CSPM ツールの出力を取り込む**設計です。Wazuh 連携と同じ形です。

- Prowler（OSS、AWS/Azure/GCP）
- ScoutSuite（OSS）
- AWS Security Hub

取り込みが 1 件も無い間、`/cloud-security` は「未計測」と表示します。0 点でも 100% 準拠でもありません。

## エンドポイント

```
POST /api/v1/cloud/findings/import
Authorization: Bearer <JWT または API キー>
Content-Type: application/json
```

認証必須です（`viewer` ロールは 403）。`/api/v1/ingest/*` のような無認証の口ではありません — 所見の書き込みは運用者・CI からの操作であるためです。

### リクエスト

```json
{
  "provider": "aws",
  "account_id": "123456789012",
  "account_name": "prod",
  "findings": [
    {
      "check_id": "s3_bucket_public_access",
      "check_name": "S3 バケットが全体公開されています",
      "severity": "critical",
      "status": "FAIL",
      "resource_type": "AwsS3Bucket",
      "resource_id": "arn:aws:s3:::my-bucket",
      "resource_name": "my-bucket",
      "region": "ap-northeast-1",
      "description": "バケットポリシーが Principal:* を許可しています",
      "remediation": "パブリックアクセスブロックを有効にしてください",
      "compliance_frameworks": ["CIS-1.5", "SOC2"]
    }
  ]
}
```

| 項目 | 必須 | 備考 |
|---|---|---|
| `provider` | ○ | `aws` / `azure` / `gcp` / `alibaba` |
| `account_id` | ○ | クラウド側のアカウント識別子。未登録なら自動で登録される |
| `check_id` | ○ | 所見の同一性判定に使う |
| `resource_id` | ○ | 同上 |
| `severity` | | `critical` / `high` / `medium` / `low`。`informational` は `low` に寄せる。不明な値は `medium` |
| `status` | | `PASS` は所見にせず、既に開いている同じ所見を `resolved` にする |
| `region` | | 同一性判定に含む。省略時は空文字 |

### レスポンス

```json
{
  "account_id": "0f2c...",
  "provider": "aws",
  "imported": 42,
  "resolved": 3,
  "rejected": 1,
  "errors": ["findings[7]: check_id がありません"]
}
```

不備のある 1 件で全体を落としません。何が落ちたかは `errors` に入ります。

## 繰り返し実行してよい

CI や cron から定期実行する前提で作っています。

- **同じ所見を再取り込みしても行は増えません。** `first_seen_at` は最初の検知時刻を保ち、`last_seen_at` だけが進みます（一意性は `uq_cspm_findings_identity`。同一性は アカウント × チェック × 資源 × リージョン）
- **担当者の判断は上書きしません。** `suppressed` / `accepted_risk` にした所見は、再検出されても `open` に戻りません。それ以外は `open` に戻ります
- 取り込みのたびに `cspm_accounts` の `posture_score` / `critical_findings` / `high_findings` / `last_scanned_at` を数え直します

## Prowler からの取り込み例

Prowler 風のキー名（`CheckID` / `CheckTitle` / `ResourceArn` / `Remediation.Recommendation.Text` / `Compliance` オブジェクト）も読めるようにしてあります。ただし**これは各ツールの公開フィールド名から起こしたもので、実際の出力に当てて検証はしていません**。バージョンによって差があるため、下記のように `jq` で正規形へ寄せるのが確実です。

```bash
prowler aws --output-formats json --output-directory /tmp/prowler

jq -n --arg acct "$(aws sts get-caller-identity --query Account --output text)" '
  {
    provider: "aws",
    account_id: $acct,
    account_name: "prod",
    findings: [inputs[] | {
      check_id:    .CheckID,
      check_name:  .CheckTitle,
      severity:    .Severity,
      status:      .Status,
      resource_type: .ResourceType,
      resource_id: (.ResourceArn // .ResourceId),
      region:      .Region,
      description: .StatusExtended,
      remediation: .Remediation.Recommendation.Text,
      compliance_frameworks: (.Compliance | keys)
    }]
  }' /tmp/prowler/*.json > /tmp/import.json

curl -sS -X POST "$API_URL/api/v1/cloud/findings/import" \
  -H "Authorization: Bearer $EDR_TOKEN" \
  -H 'Content-Type: application/json' \
  --data @/tmp/import.json
```

`jq` のフィールド名は実際の Prowler 出力に合わせて調整してください。上のマッピングは未検証です。

## 確認

取り込み後、`GET /api/v1/cloud/posture?provider=aws` の `data_available` が `true` になり、画面が「未計測」から実データ表示に変わります。

```bash
curl -sS "$API_URL/api/v1/cloud/posture?provider=aws" \
  -H "Authorization: Bearer $EDR_TOKEN" | jq '{data_available, posture_score, findings}'
```

## 関連

- `server/internal/api/handlers/cloud_findings_import.go` — 取り込み本体
- `server/internal/api/handlers/cloud_posture_handler.go` — 表示側
- `server/migrations/381_cspm_findings_import.sql` — 一意制約と `posture_score` の桁拡張
- `wazuh/` — 同じ「外部ツールの結果を取り込む」形の先例
