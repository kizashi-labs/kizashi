package awsscan

// 各チェックが呼ぶ API だけを狭いインターフェースで受ける。
// SDK のクライアント構造体をそのまま引き回すと、テストが実 AWS に
// 接続せざるを得なくなる。ここに並ぶメソッドが、そのまま
// docs/CSPMスキャナ_AWS.md の最小権限ポリシーに対応する。
//
// 読み取り専用。書き込み・削除の API は 1 つも含めない。

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/efs"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
)

// IAMAPI — iam:GetAccountSummary / iam:GetAccountPasswordPolicy /
// iam:GenerateCredentialReport / iam:GetCredentialReport
//
// GenerateCredentialReport について: このパッケージで唯一「読み取り」でない
// 名前の API になる。顧客の資源は 1 つも変更しない ---IAM が自アカウントの
// 認証情報一覧を CSV に書き出すだけで、ユーザー・キー・ポリシーのいずれにも
// 触れない。AWS のマネージドポリシー SecurityAudit にも含まれている。
//
// 必要なのは、これ無しでは認証情報レポートが読めないため。レポートは
// 4 時間で失効し、生成されていないアカウントでは GetCredentialReport が
// CredentialReportNotPresentException を返す。生成を呼ばない設計にすると、
// 顧客が別途生成していない限り CIS 1.10 / 1.12 / 1.14 が常に「未計測」に
// なる。測れるものを測らないまま unknown を出し続けるのは、この製品が
// 避けようとしている状態そのものなので、例外として呼ぶ。
//
// docs/CSPMスキャナ_AWS.md にも同じ説明を書いてある。顧客への約束は
// 「読み取りしかしない」ではなく「顧客の資源を変更する API は呼ばない」。
type IAMAPI interface {
	GetAccountSummary(ctx context.Context, in *iam.GetAccountSummaryInput, opts ...func(*iam.Options)) (*iam.GetAccountSummaryOutput, error)
	GetAccountPasswordPolicy(ctx context.Context, in *iam.GetAccountPasswordPolicyInput, opts ...func(*iam.Options)) (*iam.GetAccountPasswordPolicyOutput, error)
	GenerateCredentialReport(ctx context.Context, in *iam.GenerateCredentialReportInput, opts ...func(*iam.Options)) (*iam.GenerateCredentialReportOutput, error)
	GetCredentialReport(ctx context.Context, in *iam.GetCredentialReportInput, opts ...func(*iam.Options)) (*iam.GetCredentialReportOutput, error)
	// iam:ListPolicies / iam:GetPolicyVersion — CIS 1.16 (管理者権限の直接付与)
	ListPolicies(ctx context.Context, in *iam.ListPoliciesInput, opts ...func(*iam.Options)) (*iam.ListPoliciesOutput, error)
	GetPolicyVersion(ctx context.Context, in *iam.GetPolicyVersionInput, opts ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error)
}

// EC2API — ec2:DescribeRegions / ec2:DescribeSecurityGroups / ec2:GetEbsEncryptionByDefault
type EC2API interface {
	DescribeRegions(ctx context.Context, in *ec2.DescribeRegionsInput, opts ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error)
	DescribeSecurityGroups(ctx context.Context, in *ec2.DescribeSecurityGroupsInput, opts ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error)
	GetEbsEncryptionByDefault(ctx context.Context, in *ec2.GetEbsEncryptionByDefaultInput, opts ...func(*ec2.Options)) (*ec2.GetEbsEncryptionByDefaultOutput, error)
}

// S3API — s3:ListAllMyBuckets / s3:GetBucketPublicAccessBlock /
// s3:GetEncryptionConfiguration / s3:GetBucketLocation
type S3API interface {
	ListBuckets(ctx context.Context, in *s3.ListBucketsInput, opts ...func(*s3.Options)) (*s3.ListBucketsOutput, error)
	GetPublicAccessBlock(ctx context.Context, in *s3.GetPublicAccessBlockInput, opts ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error)
	GetBucketEncryption(ctx context.Context, in *s3.GetBucketEncryptionInput, opts ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error)
}

// S3ControlAPI — s3:GetAccountPublicAccessBlock
type S3ControlAPI interface {
	GetPublicAccessBlock(ctx context.Context, in *s3control.GetPublicAccessBlockInput, opts ...func(*s3control.Options)) (*s3control.GetPublicAccessBlockOutput, error)
}

// CloudTrailAPI — cloudtrail:DescribeTrails
type CloudTrailAPI interface {
	DescribeTrails(ctx context.Context, in *cloudtrail.DescribeTrailsInput, opts ...func(*cloudtrail.Options)) (*cloudtrail.DescribeTrailsOutput, error)
}

// RDSAPI — rds:DescribeDBInstances
type RDSAPI interface {
	DescribeDBInstances(ctx context.Context, in *rds.DescribeDBInstancesInput, opts ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error)
}

// EFSAPI — elasticfilesystem:DescribeFileSystems
type EFSAPI interface {
	DescribeFileSystems(ctx context.Context, in *efs.DescribeFileSystemsInput, opts ...func(*efs.Options)) (*efs.DescribeFileSystemsOutput, error)
}
