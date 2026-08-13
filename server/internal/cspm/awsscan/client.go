// Package awsscan は AWS アカウントの設定を読み取り、CIS AWS Foundations
// Benchmark 相当の項目を検査する。
//
// 設計の前提:
//
//   - 顧客の長期アクセスキーは預からない。顧客側に読み取り専用ロールを作って
//     もらい、外部 ID 付きの AssumeRole で一時credentialを得る。外部 ID は
//     confused deputy 対策で、テナントごとに異なる値を使う。
//   - 必要な API 呼び出しは checks.go に列挙したものだけ。これに対応する
//     最小権限ポリシーは docs/CSPMスキャナ_AWS.md に載せている。
//     マネージドポリシー SecurityAudit でも足りるが、どの action が
//     含まれるかは AWS 側の都合で変わるため、明示ポリシーを正とする。
//   - 読み取りしかしない。書き込み・削除の API は一切呼ばない。
//
// 検証状況: このパッケージは実 AWS アカウントに対して実行していない。
// テストは AWS API の応答を差し替えた擬似クライアントに対するもので、
// 「判定ロジックが正しい」ことは示すが「実際の API 応答を正しく読める」ことは
// 示さない。実アカウントでの初回実行までは未検証として扱うこと。
package awsscan

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// Credentials は検査対象アカウントへの入り方。
type Credentials struct {
	// RoleARN は顧客アカウント側の読み取り専用ロール。
	RoleARN string
	// ExternalID は AssumeRole の外部 ID。空文字は許さない
	// (第三者が ARN を推測して引き受けられる状態になるため)。
	ExternalID string
	// Region は最初に接続するリージョン。空なら ap-northeast-1。
	Region string
}

// Validate は引受に足る値が揃っているかを見る。
func (c Credentials) Validate() error {
	if strings.TrimSpace(c.RoleARN) == "" {
		return errors.New("ロール ARN が設定されていません")
	}
	if !strings.HasPrefix(c.RoleARN, "arn:") || !strings.Contains(c.RoleARN, ":role/") {
		return fmt.Errorf("ロール ARN の形式が不正です: %s", c.RoleARN)
	}
	// 外部 ID が無いロールは、ARN を知っている誰でも引き受けられる。
	// 任意項目にすると「とりあえず空で登録」が常態化するため必須にする。
	if strings.TrimSpace(c.ExternalID) == "" {
		return errors.New("外部 ID が設定されていません (confused deputy 対策のため必須)")
	}
	return nil
}

func (c Credentials) region() string {
	if c.Region != "" {
		return c.Region
	}
	return "ap-northeast-1"
}

// Clients は 1 リージョン分の API クライアント一式。
// 各フィールドは checks.go が要求する狭いインターフェースで、テストでは
// 擬似実装に差し替える。
type Clients struct {
	IAM        IAMAPI
	EC2        EC2API
	S3         S3API
	S3Control  S3ControlAPI
	CloudTrail CloudTrailAPI

	// AccountID は AssumeRole 後に判明する検査対象アカウント。
	// 所見の resource_id に使う。
	AccountID string
	// Region はこのクライアント一式が向いているリージョン。
	Region string
}

// Connect はロールを引き受け、指定リージョンのクライアント一式を返す。
//
// 引受に失敗した場合はここで返す。呼び出し側はこのエラーを
// 「検査結果が全部不合格」ではなく「検査できなかった」として扱うこと。
// 接続不良を不合格として記録すると、権限設定のミスが
// 「セキュリティ上の問題が大量にある」という表示に化ける。
func Connect(ctx context.Context, creds Credentials) (*Session, error) {
	if err := creds.Validate(); err != nil {
		return nil, err
	}

	base, err := config.LoadDefaultConfig(ctx, config.WithRegion(creds.region()))
	if err != nil {
		return nil, fmt.Errorf("AWS 設定の読み込みに失敗しました: %w", err)
	}

	// 引き受ける「側」の身元があるかを先に確かめる。
	//
	// LoadDefaultConfig は認証情報が 1 つも無くても成功するため、これを
	// 省くと最初の失敗が AssumeRole のエラーとして出る。そのメッセージは
	// 「ARN/外部 ID/信頼ポリシーを確認」と促すので、実際にはサーバ側の
	// 設定漏れなのに顧客アカウント側を疑わせてしまう。最も起こりやすい
	// 初回の失敗なので、ここで切り分ける。
	if _, err := base.Credentials.Retrieve(ctx); err != nil {
		return nil, fmt.Errorf(
			"サーバ側の AWS 認証情報が見つかりません。AssumeRole を呼ぶ主体が無いためスキャンできません。"+
				"AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY を設定するか、"+
				"EC2 上ならインスタンスロールを付与してください "+
				"(docs/CSPMスキャナ_AWS.md の「サーバ側の身元」): %w", err)
	}

	stsClient := sts.NewFromConfig(base)
	provider := stscreds.NewAssumeRoleProvider(stsClient, creds.RoleARN, func(o *stscreds.AssumeRoleOptions) {
		o.ExternalID = aws.String(creds.ExternalID)
		o.RoleSessionName = "kizashi-cspm"
		// 1 回のスキャンが収まる長さ。長くしても得が無い。
		o.Duration = 30 * time.Minute
	})

	cfg := base.Copy()
	cfg.Credentials = aws.NewCredentialsCache(provider)

	// 引き受けられたことと、対象アカウント ID をここで確定させる。
	// 失敗するなら検査を始める前に失敗させたい。
	ident, err := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, fmt.Errorf("ロールの引き受けに失敗しました (ARN/外部 ID/信頼ポリシーを確認してください): %w", err)
	}

	return &Session{cfg: cfg, accountID: aws.ToString(ident.Account)}, nil
}

// Session は引受済みの資格情報。リージョンごとのクライアントはここから作る。
// 引受は 1 回だけで、リージョンを変えても再度 AssumeRole しない
// (aws.CredentialsCache が一時credentialを共有する)。
type Session struct {
	cfg       aws.Config
	accountID string
}

// AccountID は検査対象アカウント。
func (s *Session) AccountID() string { return s.accountID }

// Clients は指定リージョン向けのクライアント一式を返す。
func (s *Session) Clients(region string) *Clients {
	cfg := s.cfg.Copy()
	if region != "" {
		cfg.Region = region
	}
	return &Clients{
		IAM:        iam.NewFromConfig(cfg),
		EC2:        ec2.NewFromConfig(cfg),
		S3:         s3.NewFromConfig(cfg),
		S3Control:  s3control.NewFromConfig(cfg),
		CloudTrail: cloudtrail.NewFromConfig(cfg),
		AccountID:  s.accountID,
		Region:     cfg.Region,
	}
}

// Regions は有効化されているリージョンを返す。
// 明示指定が無いときの走査対象。
func (s *Session) Regions(ctx context.Context) ([]string, error) {
	out, err := s.Clients("").EC2.DescribeRegions(ctx, &ec2.DescribeRegionsInput{})
	if err != nil {
		return nil, fmt.Errorf("リージョン一覧の取得に失敗しました: %w", err)
	}
	regions := make([]string, 0, len(out.Regions))
	for _, r := range out.Regions {
		if name := aws.ToString(r.RegionName); name != "" {
			regions = append(regions, name)
		}
	}
	sort.Strings(regions)
	return regions, nil
}
