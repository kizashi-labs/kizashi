# CSPM スキャナ (AWS)

AWS アカウントに接続して設定を検査し、所見を `cspm_findings` に入れる。
実装は `server/internal/cspm/awsscan/`。

## 検証状況（先に読むこと）

**このスキャナは実 AWS アカウントに対して実行していない。** テストは AWS API の応答を差し替えた擬似クライアントに対するもので、「判定ロジックが正しい」ことは示すが「実際の API 応答をこの形で受け取れるか」は示さない。

突き合わせが済むまでは、この機能の出力を顧客に見せる判断材料にしないこと。手順は次節。

## 初回検証の手順

**捨ててよい検証用アカウント**で実施すること。読み取りしかしないが、未検証のコードを本番アカウントに向ける理由がない。

### 1. 実行してログを見る

```bash
docker compose logs -f server-api | grep 'CSPM(AWS)'
```

スキャンを開始し、完了ログを見る。

```
CSPM(AWS): スキャンが完了しました account=... aws_account=123456789012
  regions=17 findings=8 resolved=0 unmeasured=3 duration=42s
```

**`unmeasured` が 0 でなければ、そこから見る。** 続く警告行に 1 件ずつ理由が出る。

```
CSPM(AWS): 検査できなかった項目があります check_id=aws-s3-bucket-encryption
  region=us-east-1 reason=取得に失敗: AccessDenied
```

`unmeasured` は所見にならないので、ここを見ないと**存在自体が見えない**。「所見が少ない」のと「検査できていない」のは全く違う。

### 2. 3 点を突き合わせる

1. 所見の件数と内容が、コンソールで見た実態と合っているか
2. 合格した項目が誤って所見になっていないか（**偽陽性**）
3. コンソールで問題がある項目が所見に出ているか（**偽陰性**）

偽陰性のほうが危険なので、**わざと 1 つ穴を空けて検出されるか**を見るのが確実。検証用アカウントで、たとえば次のいずれかを一時的に作る。

- セキュリティグループで 22 番を `0.0.0.0/0` に開ける → `aws-ec2-sg-ssh-open`
- バケットのパブリックアクセスブロックを 1 項目外す → `aws-s3-bucket-public-access-block`
- EBS の既定の暗号化を切る → `aws-ec2-ebs-default-encryption`

検出できたら元に戻し、再スキャンして所見が `resolved` になることも確認する（合格に転じた項目が閉じられる経路の確認）。

### 3. 特に疑うべき箇所

実装上、**推測に頼っていて外れやすい**のは次の 4 つ。ここを重点的に見ること。

| 箇所 | 外れたときの症状 |
|---|---|
| **エラー文字列での判定** | `s3control.GetPublicAccessBlock` と `GetBucketEncryption` は「未設定」を SDK のエラー文字列（`NoSuchPublicAccessBlockConfiguration` / `ServerSideEncryptionConfigurationNotFoundError`）で見分けている。文字列が違えば **fail になるべきものが unknown** になる |
| **`ListBuckets` のリージョン絞り込み** | `BucketRegion` で絞れていないと、別リージョンのバケットに対して呼んでリダイレクトエラーになり unknown が大量に出る。あるいは同じバケットが複数リージョンで重複して所見になる |
| **`GetAccountSummary` のキー名** | `AccountMFAEnabled` / `AccountAccessKeysPresent` が返ってこなければ、ルート関連の critical 2 件が unknown になる |
| **`DescribeRegions` の範囲** | 有効化していないリージョンまで返ると、そのリージョンの全項目が unknown になる。`regions` を明示指定すれば回避できる |

いずれも**症状は「unknown が増える」**であって「誤った所見が出る」ではない。設計上そうしてあるので、手順 1 のログが判断材料になる。

### 4. 記録する

結果は `docs/results/` に残し、`docs/debt/P5.md` の P5-34 を更新すること。最低限、実行したアカウントの構成（リージョン数・バケット数・SG 数）、所見件数、unmeasured の内訳、偽陽性・偽陰性の有無。

## なぜ自前で検査するのか

外部ツール（Prowler 等）の出力を取り込む経路は別にある（`docs/CSPM所見の取り込み.md`）。そちらは顧客側で Prowler の運用・cron・IAM ロール・送信スクリプトを構築してもらう必要があり、SOC 人員が薄い組織では現実的でない。加えて、その一連が壊れても画面は古いデータを出し続けるため、「測っていない」ことに気づけない。

自前で検査すれば、顧客の作業はロールを 1 つ作るだけになる。代償として、チェック項目の維持と顧客クラウドへの読み取り権限の保管がこちらの責任になる。

## 資格情報の扱い

**長期のアクセスキーは受け取らない。** 顧客アカウント側に読み取り専用ロールを作ってもらい、その ARN と外部 ID だけを保存する。実際の認証は実行時の `AssumeRole` で、有効期間 30 分の一時credentialを使う。ディスクには残らない。

外部 ID は必須にしてある。省略可能にすると「とりあえず空で登録」が常態化し、ロール ARN を知った第三者が引き受けられる状態（confused deputy）になる。

### サーバ側の身元（見落としやすい前提）

**`AssumeRole` を呼ぶには、呼ぶ側にも AWS の身元が要る。** これが無いとスキャンは必ず失敗する。顧客ロールの設定がいくら正しくても関係ない。

| 配置 | 設定 |
|---|---|
| EC2 上 | インスタンスロールを付与する。環境変数は不要（SDK が IMDS から取得する） |
| docker compose / オンプレ | `.env` に `AWS_REGION` / `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` |

このキーに与える権限は**対象ロールを引き受けることだけ**にすること。顧客クラウドを読む権限はロール側にあるので、こちらに足す理由がない。

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "sts:AssumeRole",
    "Resource": "arn:aws:iam::<TARGET_ACCOUNT_ID>:role/KizashiCSPMReadOnly"
  }]
}
```

設定できているかは、コンテナ内の環境変数で確認する。

```bash
docker compose exec api env | grep AWS_ACCESS_KEY_ID
```

空なら `.env` に書いても届いていない。`docker-compose.yml` の `api` サービスが `AWS_*` を environment に渡しているか確認すること（`deploy/docker-compose.prod.yml` は `env_file` 方式なので `.env.prod` に書けば届く）。

認証情報が無い状態でスキャンすると、`scan_error` に次が入る。

```
サーバ側の AWS 認証情報が見つかりません。AssumeRole を呼ぶ主体が無いためスキャンできません。
```

これが出たら顧客アカウント側ではなくサーバ側を見ること。

### 顧客側に作ってもらうロール

信頼ポリシー（`<KIZASHI_ACCOUNT_ID>` と `<EXTERNAL_ID>` は発行した値に置き換える）:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "AWS": "arn:aws:iam::<KIZASHI_ACCOUNT_ID>:root" },
    "Action": "sts:AssumeRole",
    "Condition": { "StringEquals": { "sts:ExternalId": "<EXTERNAL_ID>" } }
  }]
}
```

権限ポリシー。**現在の実装が実際に呼ぶ API だけ**を列挙している（`server/internal/cspm/awsscan/api.go` と 1 対 1 で対応する）。

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "sts:GetCallerIdentity",
      "iam:GetAccountSummary",
      "iam:GetAccountPasswordPolicy",
      "ec2:DescribeRegions",
      "ec2:DescribeSecurityGroups",
      "ec2:GetEbsEncryptionByDefault",
      "s3:ListAllMyBuckets",
      "s3:GetBucketPublicAccessBlock",
      "s3:GetEncryptionConfiguration",
      "s3:GetAccountPublicAccessBlock",
      "cloudtrail:DescribeTrails"
    ],
    "Resource": "*"
  }]
}
```

ロールの最大セッション時間は **3600 秒以上**にしてもらうこと。スキャナは 30 分のセッションを要求するので、これより短いと `AssumeRole` 自体が失敗する。

マネージドポリシーの `SecurityAudit` でも動くはずだが、そこに何が含まれるかは AWS 側の都合で変わる。**上の明示ポリシーを正とする。** チェックを追加したら、このリストと `api.go` を必ず一緒に更新すること。

初回検証では `SecurityAudit` を使わないこと。明示ポリシーだけで動かせば、リストに漏れがあった項目が `unknown` + `AccessDenied` として現れ、何が足りないかがそのまま分かる。`SecurityAudit` を付けると余分な権限で動いてしまい、顧客に案内するポリシーが正しいか確認できない。

書き込み・削除の API は 1 つも含まれていない。含めないこと。

## 検査項目

現在 12 項目。CIS AWS Foundations Benchmark の項番に寄せてある。

| check_id | 内容 | 重大度 | 範囲 |
|---|---|---|---|
| `aws-iam-root-mfa` | ルートアカウントの MFA | critical | アカウント |
| `aws-iam-root-access-key` | ルートのアクセスキーが無い | critical | アカウント |
| `aws-iam-password-min-length` | パスワード最小長 14 文字 | medium | アカウント |
| `aws-iam-password-reuse-prevention` | パスワード再利用防止 24 世代 | low | アカウント |
| `aws-s3-account-public-access-block` | S3 アカウント全体のブロック | high | アカウント |
| `aws-cloudtrail-multiregion` | 全リージョン証跡＋ログ検証 | high | アカウント |
| `aws-s3-bucket-public-access-block` | バケット単位のブロック | critical | リージョン |
| `aws-s3-bucket-encryption` | バケットの既定の暗号化 | medium | リージョン |
| `aws-ec2-sg-ssh-open` | SSH(22) の全世界公開 | high | リージョン |
| `aws-ec2-sg-rdp-open` | RDP(3389) の全世界公開 | high | リージョン |
| `aws-ec2-default-sg-restricted` | 既定 SG に規則が残っていない | medium | リージョン |
| `aws-ec2-ebs-default-encryption` | EBS の既定の暗号化 | medium | リージョン |

CIS 全体（AWS だけで 200 項目超）には遠く及ばない。資源を 1 件ずつ舐める必要があるもの（認証情報レポート、IAM ポリシー全走査、RDS/EFS の暗号化など）は第 2 弾に回している。

**`check_id` は所見の同一性に使う。一度出したら変えないこと。** 変えると同じ問題が別の所見として増える。

## 未計測を pass にも fail にもしない

権限不足や API エラーで読めなかった項目は `unknown` になり、**所見にならない**。`ScanResult.Errors` に理由が入り、ログに出る。

これを pass に倒すと権限設定のミスが「問題なし」になり、fail に倒すと「重大な問題が大量にある」になる。どちらもこの製品が過去に踏んだ失敗（`docs/debt/P5.md` の P5-34）と同じ形なので、分けて持つ。

同じ理由で、スキャンが失敗したときの `scan_status` は `completed` ではなく `error` にし、`scan_error` に理由を残す。

## 使い方

### 1. アカウントを登録する

取り込み API と同じく、`cspm_accounts` に行があればよい。まだ無ければ取り込み API か、直接 INSERT で作る。

### 2. 引受ロールを登録する

```bash
curl -sS -X PUT "$API_URL/api/v1/admin/cspm-enhanced/accounts/$ACCOUNT_UUID/credentials" \
  -H "Authorization: Bearer $EDR_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "role_arn": "arn:aws:iam::123456789012:role/KizashiCSPMReadOnly",
    "external_id": "'"$EXTERNAL_ID"'",
    "regions": ["ap-northeast-1"]
  }'
```

`regions` を省略すると、有効化されている全リージョンを走査する。SMB の構成では東京 1 つだけということも多く、その場合は明示したほうが所要時間と API 呼び出し回数が桁で減る。

`viewer` ロールは 403。顧客クラウドへの読み取り権限に直結するため。

### 3. スキャンする

```bash
curl -sS -X POST "$API_URL/api/v1/admin/cspm-enhanced/accounts/$ACCOUNT_UUID/scan" \
  -H "Authorization: Bearer $EDR_TOKEN"
```

非同期で走るので **202** が返る。「開始した」であって「終わった」ではない。進行状況は:

```bash
curl -sS "$API_URL/api/v1/admin/cspm-enhanced/accounts" \
  -H "Authorization: Bearer $EDR_TOKEN" | jq '.accounts[] | {account_id, scan_status, posture_score}'
```

`scan_status` は `idle` → `scanning` → `completed` または `error`。上限は 15 分。

引受ロールが未登録の AWS アカウントは **400**（`cspm_credentials_not_configured`）。AWS 以外のアカウントは **501**（`cspm_scanner_not_implemented`）。どちらも「走ったふり」はしない。

## 所見の書き込みは 1 実装

取り込み API も自前スキャナも `store.CSPMStore`（`server/internal/store/cspm.go`）を通る。同一性判定・解決済みの扱い・集計の更新が経路によってずれないようにするため。

この製品は検知ルールで「同じ概念を 2 箇所が別実装で持つ」失敗を既に踏んでいる（`docs/検知ルールの二重管理とデプロイ.md`）。CSPM 側は最初から単一実装にしてある。**チェックを追加するときも、書き込みは必ずこの store を通すこと。**

合格した項目は所見を作らず、開いている同じ所見を `resolved` にする。`suppressed` / `accepted_risk` は担当者の判断なので、再検出しても `open` に戻さない。

検査できなかった項目は、開いている所見に**一切触れない**。読めなかったことを「直った」とみなすと、権限が外れた瞬間に全所見が消えて「問題なし」に見える。

## ネットワーク要件

サーバから AWS API への外向き HTTPS が必要（`sts`, `iam`, `ec2`, `s3`, `s3-control`, `cloudtrail` の各エンドポイント）。閉域に置いた構成では動かないので、その場合は取り込み API を使うこと。

あわせて、上の「サーバ側の身元」も満たしていること。ネットワークが通っていても身元が無ければ `AssumeRole` の時点で失敗する。

## 項目を追加する

1. `checks.go` に `Check` を足す（`Checks()` の返り値に追加）
2. 新しい API を呼ぶなら `api.go` のインターフェースに足す
3. **このドキュメントの最小権限ポリシーに action を足す** — 忘れると顧客側で権限不足になり、その項目は永久に `unknown` になる
4. `checks_test.go` に擬似クライアントでのテストを足す。読めなかった場合が `unknown` になることも見る

## 関連

- `docs/CSPM所見の取り込み.md` — 外部ツールの出力を取り込む経路
- `server/internal/cspm/awsscan/` — スキャナ本体
- `server/internal/store/cspm.go` — 所見の書き込み（単一実装）
- `server/migrations/426_cspm_aws_scanner.sql` — 外部 ID・スキャン状態の列
- `docs/debt/P5.md` の P5-34 — 経緯
