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
      "iam:GenerateCredentialReport",
      "iam:GetCredentialReport",
      "iam:ListPolicies",
      "iam:GetPolicyVersion",
      "ec2:DescribeRegions",
      "ec2:DescribeSecurityGroups",
      "ec2:GetEbsEncryptionByDefault",
      "s3:ListAllMyBuckets",
      "s3:GetBucketPublicAccessBlock",
      "s3:GetEncryptionConfiguration",
      "s3:GetAccountPublicAccessBlock",
      "cloudtrail:DescribeTrails",
      "rds:DescribeDBInstances",
      "elasticfilesystem:DescribeFileSystems"
    ],
    "Resource": "*"
  }]
}
```

ロールの最大セッション時間は **3600 秒以上**にしてもらうこと。スキャナは 30 分のセッションを要求するので、これより短いと `AssumeRole` 自体が失敗する。

マネージドポリシーの `SecurityAudit` でも動くはずだが、そこに何が含まれるかは AWS 側の都合で変わる。**上の明示ポリシーを正とする。** チェックを追加したら、このリストと `api.go` を必ず一緒に更新すること。

初回検証では `SecurityAudit` を使わないこと。明示ポリシーだけで動かせば、リストに漏れがあった項目が `unknown` + `AccessDenied` として現れ、何が足りないかがそのまま分かる。`SecurityAudit` を付けると余分な権限で動いてしまい、顧客に案内するポリシーが正しいか確認できない。

### `iam:GenerateCredentialReport` について

このリストで唯一、名前が「読み取り」でない API。**顧客の資源は 1 つも変更しない。**
IAM が自アカウントの認証情報一覧を CSV に書き出すだけで、ユーザー・アクセスキー・
ポリシーのいずれにも触れない。AWS のマネージドポリシー `SecurityAudit` にも含まれている。

必要なのは、これ無しでは認証情報レポートが読めないため。レポートは 4 時間で失効し、
生成されていないアカウントでは `GetCredentialReport` が
`CredentialReportNotPresentException` を返す。生成を呼ばない設計にすると、顧客が
別途生成していない限り CIS 1.10 / 1.12 / 1.14 が**常に「未計測」**になる。測れるものを
測らないまま `unknown` を出し続けるのは、この製品が避けようとしている状態そのものなので、
例外として呼ぶことにした。

したがって顧客への約束は「読み取りしかしない」ではなく、**「顧客の資源を変更する API は
呼ばない」**である。上のリストにこれ以外の変更系 API は 1 つも無く、今後も追加しないこと。

## 検査項目

現在 18 項目。CIS AWS Foundations Benchmark の項番に寄せてある。

| check_id | 内容 | 重大度 | 範囲 |
|---|---|---|---|
| `aws-iam-root-mfa` | ルートアカウントの MFA | critical | アカウント |
| `aws-iam-root-access-key` | ルートのアクセスキーが無い | critical | アカウント |
| `aws-iam-password-min-length` | パスワード最小長 14 文字 | medium | アカウント |
| `aws-iam-password-reuse-prevention` | パスワード再利用防止 24 世代 | low | アカウント |
| `aws-iam-user-mfa` | コンソールを使える IAM ユーザーの MFA (CIS 1.10) | high | アカウント |
| `aws-iam-unused-credentials` | 45 日以上未使用の認証情報 (CIS 1.12) | medium | アカウント |
| `aws-iam-access-key-rotation` | 90 日を超えたアクセスキー (CIS 1.14) | medium | アカウント |
| `aws-iam-no-full-admin-policy` | 管理者権限 (*:*) の自作ポリシー (CIS 1.16) | high | アカウント |
| `aws-s3-account-public-access-block` | S3 アカウント全体のブロック | high | アカウント |
| `aws-cloudtrail-multiregion` | 全リージョン証跡＋ログ検証 | high | アカウント |
| `aws-s3-bucket-public-access-block` | バケット単位のブロック | critical | リージョン |
| `aws-s3-bucket-encryption` | バケットの既定の暗号化 | medium | リージョン |
| `aws-ec2-sg-ssh-open` | SSH(22) の全世界公開 | high | リージョン |
| `aws-ec2-sg-rdp-open` | RDP(3389) の全世界公開 | high | リージョン |
| `aws-ec2-default-sg-restricted` | 既定 SG に規則が残っていない | medium | リージョン |
| `aws-ec2-ebs-default-encryption` | EBS の既定の暗号化 | medium | リージョン |
| `aws-rds-storage-encrypted` | RDS のストレージ暗号化 | high | リージョン |
| `aws-efs-encrypted` | EFS の暗号化 | high | リージョン |

CIS 全体（AWS だけで 200 項目超）には遠く及ばない。

IAM 系の 3 項目（`aws-iam-user-mfa` / `aws-iam-unused-credentials` / `aws-iam-access-key-rotation`）は
認証情報レポート 1 本から導く。ユーザーを 1 人ずつ舐めると人数分の API 呼び出しになるため。
所見の `resource_id` は IAM ユーザー名で、ルートアカウントは除外する（ルートの MFA は
`aws-iam-root-mfa` が見るので、同じ問題で所見が 2 件立たないようにしている）。

### 暗号化の 3 項目の違い

`aws-ec2-ebs-default-encryption` は「**これから作る** EBS が暗号化されるか」の
アカウント設定を見る。`aws-rds-storage-encrypted` と `aws-efs-encrypted` は
「**既にある**資源が暗号化されているか」を 1 件ずつ見る。既定を有効にしても
それ以前に作った資源は暗号化されないので、両方要る。

RDS も EFS も**作成後に暗号化を有効にできない**。是正はスナップショット
／新規作成からの移行になるため、重大度を high にし、Remediation にもその
手順を書いている。「設定を変えれば済む」と誤解させると担当者が作業量を
見誤る。テストで Remediation の文言も固定してある。

同じ理由で、`StorageEncrypted` / `Encrypted` が応答に無い場合は fail では
なく `unknown` にする。nil を false に丸めると、応答に含まれなかっただけの
資源に対して「本番 DB を作り直せ」という指示が立つ。

`aws-iam-no-full-admin-policy` が見るのは **顧客が作って、実際に誰かに付いている**
ポリシーだけ（`Scope=Local` かつ `OnlyAttached=true`）。

- AWS 管理ポリシーを除くのは、`AdministratorAccess` を持つ管理者が多くの組織で
  正当だから。毎回 high で挙げると一覧が実務に耐えない。CIS の監査手順も
  `--scope Local` を使う。
- どこにも付いていないポリシーを除くのは、その時点で誰の権限にもなっていないから。
  打ち手が「消す」しか無い所見で一覧が埋まる。

判定は `Effect=Allow` かつ `Action` に `*` かつ `Resource` に `*` かつ `Condition` 無し。
`s3:*` のようなサービス全権は対象外（広いには違いないが CIS 1.16 が問うのは `*:*`）。
`NotAction` 付きの文は意味が反転するので判定しない——誤判定するくらいなら対象外にする。

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

### 4. 定期実行と通知

`EDR_CSPM_SCAN_INTERVAL_HOURS`（既定 24）ごとに、引受情報が登録済みの AWS アカウントを自動で検査する。`0` で停止（顧客の AWS を叩く処理なので、再ビルド無しで止められるようにしてある）。

結果は**既存のアラート通知チャンネル**（Slack / メール / Webhook / Teams）にそのまま流れる。CSPM 専用の送り先を作っていないのは、設定が分かれていると「片方だけ設定されていない」状態に誰も気づけないため。

**送るのは次の 3 つだけで、それ以外の回は送らない。**

| 状況 | 重大度 | 通知内容 |
|---|---|---|
| スキャンが失敗した | 8 | 「この回は 1 項目も測れていない」「画面の所見は前回のまま」 |
| 検査できなかった項目がある | 8 | 項目名と理由（`AccessDenied` の action 名まで） |
| 新しい所見が出た | 最も重い所見に合わせる（critical 9 / high 7 / medium 5 / low 4） | 項目名・資源名・リージョン |

**異常が無い回は送らない。** 毎日「異常なし」が届くと数日で読み飛ばされ、本当に伝えたい回が埋もれる。沈黙が「異常なし」を意味する設計にしてある。

**未計測（8）を新しい high の所見（7）より重くしているのは意図的。** 所見は「見つかった 1 件」だが、未計測は「何件あるか分からない」状態で、放置するとその項目は永久に「問題なし」に見え続ける。

通知が要らない環境では通知チャンネルを 1 つも設定しなければよい（定期スキャン自体は動く）。逆に、**「静かにする」方向の変更を入れるときは未計測まで一緒に黙らせないこと。** `TestUnmeasuredAlwaysNotifies` がそれを縛っている。

新しい所見の判定は `store.UpsertFinding` の戻り値（`first_seen_at = last_seen_at`）による。件数で判断していないのは、所見の総数は毎回ほぼ同じ数になり、増えたのか変わっていないのか分からないため。なお**一度解消した所見が再発した場合は「新規」に含まれない**（行が残っていて `first_seen_at` が過去のまま）。

手動スキャン（画面のボタン）では通知しない。押した本人がその場で結果を見るため。

通知のリンク先は **`/cloud-security`**（`frontend/app/cloud-security/`）。既定の `/alerts/<id>` は CSPM には対応する画面が無いので上書きしている。**画面のパスを変えるときは通知側も一緒に直すこと** — 取り残されるとリンクが 404 になり、しかも押した人以外は気づかない。

#### 通知先が 0 件のとき

`Dispatcher.Notify` は送信先が 1 つも無くても**静かに何もしない**。定期実行は人が見ていないので、それだと「通知したつもり」のまま気づかれない。伝えるべき結果があるのに送信先が無い場合は、送信をやめて警告を出す。

```
WARN CSPM(定期): 伝えるべき結果がありますが、通知チャンネルが 1 つも設定されていません
```

#### 通知チャンネルの種別が 2 語彙あった

`notification_channels` は 1 つのテーブルだが、書く側と読む側で種別名が揃っていなかった。

| | 語彙 |
|---|---|
| API / 画面が保存する値 | `webhook_slack` / `webhook_teams` / `webhook_generic` / `email` |
| `internal/notify`（既存のアラート通知）が読む値 | 同上（一致） |
| `internal/notification` の `Dispatcher` が読む値 | `slack` / `teams` / `webhook` / `email` |

このため **`webhook_*` で保存されたチャンネルは Dispatcher の送信先に一切載っていなかった。** 行は存在して `enabled = true` なのに `Notify` は静かに何もしない。手がかりは起動時の `WARN 通知チャンネルの初期化に失敗しました` 1 行だけで、画面上は「設定済み」に見える。設定キーも同様で、API は `webhook_url` に入れるのに Dispatcher の webhook は `url` を読んでいた。

CLAUDE.md が検知ルールについて警告している「同じ概念を 2 箇所が別実装で持つ」が通知でも起きていた形。**語彙を片方に寄せる移行はデータの書き換えを伴うので、まず Dispatcher が両方を受けるようにした。** 恒久対応（どちらかに統一）は別途。

**関連して、この実装中に api プロセス側の欠陥がもう 1 つ見つかったので直した。** api は通知チャンネルを**起動時に一度読むだけ**で、画面から追加・変更しても再起動するまで反映されなかった（`cmd/detection` には `settings.channels.updated` の購読が元からあり、api 側だけ抜けていた）。送信先が 0 件でも `Notify` は静かに成功するので、「設定したのに届かない、エラーも出ない」状態になる。既存の「チャンネルのテスト送信」ボタンも、起動後に作ったチャンネルでは「チャンネルが見つかりません」になっていた。api にも同じ購読を足してある。

### 「設定できているか」と「届いたか」は別の話

上の 2 つの修正で **設定が正しければ届く** ようにはなったが、**届いたかどうか** はまだ誰も見ていなかった。実機で検証したときの状態がこれで、有効 3 チャンネルのうち実際に届いたのは 1 つだけだったのに、指標は次のように出ていた。

```
EnabledChannels() = 3
FailedChannels()  = 0
```

`FailedChannels` は「センダーを作れなかった」数なので、**センダーは作れたが送信時に落ちた** チャンネル（webhook が 405、SMTP が 535）は 0 と数える。`EnabledChannels` は落ちたチャンネルまで数え込む。この 2 つだけを読むと全部届いたようにしか見えない。

そこで `Dispatcher.Notify` が `NotifyResult`（`Eligible` / `Sent` / `Failed` / `FailedNames`）を返すようにし、ファンアウト 1 回分の結末をそこで数えるようにした。

| 指標 (`component`) | 何を数えるか | 直す相手 |
|---|---|---|
| `notification_channels` | 起動・再読込時にセンダーを作れなかった | 設定（種別名・URL の欠落） |
| `notification_delivery` | 送信を試みて届かなかった（全滅／一部失敗） | 送信先の側（URL、認証、到達性） |

**送信ごとの `NotifsError` では代わりにならない。** あれは失敗の総数なので、3 チャンネル中 1 つが毎回落ちている状態と、たまたま 1 回落ちた状態が同じ増え方をする。監視を貼るなら「その通知はどこにも届かなかった」「届かない送信先が混じっている」という結末の単位が要る。

`notifyCSPM` が別に見ているのは **重大度が全チャンネルの下限に届かず 1 件も送信されなかった** 場合だけ。この回は送信を 1 件も試行していないので Dispatcher から見れば失敗 0 件で、`notification_delivery` は何も記録しない。

なお **画面の「テスト送信」が緑でも、この経路の証明にはならない。** `NotificationHandler.TestChannel` / `SettingsHandler.TestChannel` はどちらも Dispatcher を通らず、専用の `testWebhookDirect` / `testChannelWebhook` で送っている。上の語彙不一致もここでは再現しない。実配信を確認するなら、実際にスキャンを発火させて受信側で見ること。

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
