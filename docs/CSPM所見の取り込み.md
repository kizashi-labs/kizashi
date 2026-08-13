# CSPM 所見の取り込み

`/cloud-security`（クラウドセキュリティ態勢）に表示するデータを入れる手順。

## 位置づけ: 外部ツールの結果を取り込む経路

所見を入れる経路は 2 つあります。

| | |
|---|---|
| **自前の AWS スキャナ** | `server/internal/cspm/awsscan`。AWS のみ。読み取り専用ロールを引き受けて検査する。→ `docs/CSPMスキャナ_AWS.md` |
| **外部ツールの取り込み**（このドキュメント） | Azure / GCP、あるいは AWS でも CIS 全項目を見たい場合。閉域でサーバから AWS へ出られない構成でも使える |

`POST /api/v1/cloud/scan`（プロバイダ横断のスキャン）は依然 **501 Not Implemented** です。アカウント単位のスキャンは `POST /api/v1/admin/cspm-enhanced/accounts/:id/scan` を使ってください（AWS のみ）。

取り込みは、**既存の CSPM ツールの出力を取り込む**設計です。Wazuh 連携と同じ形です。

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

## 管理 API（`/api/v1/admin/cspm-enhanced/*`）

同じデータを、アカウント単位・所見単位で引くための口です。

| | |
|---|---|
| `GET /accounts` | 登録済みクラウドアカウント。`posture_score` は 0〜100 |
| `GET /findings` | 所見一覧。`provider` / `severity` / `status` / `limit` / `offset` で絞れる。既定は `status=open` |
| `GET /stats` | 全体集計 |
| `POST /accounts/:id/scan` | **501 を返します**（スキャナ未実装） |

絞り込みに想定外の値を渡すと 400 です。0 件として返すと「所見が無い」と読めてしまうためです。

### `stats` に準拠率が無い理由

`cspm_findings` に入るのは**不合格の所見だけ**で、取り込み API は `PASS` を行にせず既存の所見を `resolved` にします。つまり「何項目中何項目に合格したか」の分母が手元にありません。

以前このエンドポイントは `CIS 145/23（86.3%）` のような準拠率を固定値で返していましたが、分母が無い以上これは算出できない数字でした。現在は枠組みごとの未対応件数のみを `compliance_open_findings` として返します。

```json
{
  "total_accounts": 1, "total_findings": 2,
  "critical": 1, "high": 1, "medium": 0, "low": 0,
  "avg_posture_score": 88.5,
  "compliance_open_findings": [{"framework": "CIS-1.5", "open_findings": 2}],
  "data_available": true
}
```

`avg_posture_score` は一度もスキャン結果を取り込んでいないアカウント（`last_scanned_at IS NULL`）を除いた平均です。既定値の 0 は「最悪」ではなく「未計測」なので、混ぜるとアカウントを登録しただけでスコアが下がります。取り込みが 1 件も無ければ `null` になります。

## 関連

- `server/internal/api/handlers/cloud_findings_import.go` — 取り込み本体
- `server/internal/api/handlers/cloud_posture_handler.go` — 表示側
- `server/internal/api/handlers/cspm_enhanced_handler.go` — 管理 API（`/admin/cspm-enhanced/*`）
- `server/migrations/381_cspm_findings_import.sql` — 一意制約と `posture_score` の桁拡張
- `docs/CSPMスキャナ_AWS.md` — 自前の AWS スキャナ
- `server/internal/store/cspm.go` — 所見の書き込み（取り込みとスキャナで共通）
- `wazuh/` — 同じ「外部ツールの結果を取り込む」形の先例
