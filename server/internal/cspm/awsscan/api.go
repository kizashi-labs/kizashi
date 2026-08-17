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
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
)

// IAMAPI — iam:GetAccountSummary / iam:GetAccountPasswordPolicy
type IAMAPI interface {
	GetAccountSummary(ctx context.Context, in *iam.GetAccountSummaryInput, opts ...func(*iam.Options)) (*iam.GetAccountSummaryOutput, error)
	GetAccountPasswordPolicy(ctx context.Context, in *iam.GetAccountPasswordPolicyInput, opts ...func(*iam.Options)) (*iam.GetAccountPasswordPolicyOutput, error)
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
