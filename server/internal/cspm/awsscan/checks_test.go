package awsscan

// 判定ロジックのテスト。AWS API の応答を差し替えた擬似クライアントに対して
// 実行する。
//
// このテストが示すのは「与えられた応答を正しく判定するか」だけで、
// 「実際の AWS が返す応答をこの形で受け取れるか」は示さない。
// 実アカウントでの初回実行までは未検証として扱うこと。
//
// 特に押さえるのは、読めなかったものを pass にも fail にもしないこと。
// CSPM でこれを間違えると、権限設定のミスが「問題なし」または
// 「大量の問題あり」に化ける。

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
	s3ctypes "github.com/aws/aws-sdk-go-v2/service/s3control/types"
)

// --- 擬似クライアント ---

type fakeIAM struct {
	summary  map[string]int32
	policy   *iamtypes.PasswordPolicy
	noPolicy bool
	err      error
}

func (f fakeIAM) GetAccountSummary(context.Context, *iam.GetAccountSummaryInput, ...func(*iam.Options)) (*iam.GetAccountSummaryOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &iam.GetAccountSummaryOutput{SummaryMap: f.summary}, nil
}

func (f fakeIAM) GetAccountPasswordPolicy(context.Context, *iam.GetAccountPasswordPolicyInput, ...func(*iam.Options)) (*iam.GetAccountPasswordPolicyOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.noPolicy {
		return nil, &iamtypes.NoSuchEntityException{}
	}
	return &iam.GetAccountPasswordPolicyOutput{PasswordPolicy: f.policy}, nil
}

type fakeEC2 struct {
	groups    []ec2types.SecurityGroup
	ebsByDef  bool
	regions   []string
	err       error
	pageCalls int
}

func (f *fakeEC2) DescribeRegions(context.Context, *ec2.DescribeRegionsInput, ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	out := &ec2.DescribeRegionsOutput{}
	for _, r := range f.regions {
		out.Regions = append(out.Regions, ec2types.Region{RegionName: aws.String(r)})
	}
	return out, nil
}

func (f *fakeEC2) DescribeSecurityGroups(_ context.Context, in *ec2.DescribeSecurityGroupsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	// 2 ページに割って、ページングを実際に辿ることを確かめる。
	f.pageCalls++
	if in.NextToken == nil && len(f.groups) > 1 {
		return &ec2.DescribeSecurityGroupsOutput{
			SecurityGroups: f.groups[:1],
			NextToken:      aws.String("next"),
		}, nil
	}
	if in.NextToken != nil {
		return &ec2.DescribeSecurityGroupsOutput{SecurityGroups: f.groups[1:]}, nil
	}
	return &ec2.DescribeSecurityGroupsOutput{SecurityGroups: f.groups}, nil
}

func (f *fakeEC2) GetEbsEncryptionByDefault(context.Context, *ec2.GetEbsEncryptionByDefaultInput, ...func(*ec2.Options)) (*ec2.GetEbsEncryptionByDefaultOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &ec2.GetEbsEncryptionByDefaultOutput{EbsEncryptionByDefault: aws.Bool(f.ebsByDef)}, nil
}

type fakeS3 struct {
	buckets  []string
	pab      map[string]*s3types.PublicAccessBlockConfiguration
	pabErr   map[string]error
	encAlgo  map[string]string
	encErr   map[string]error
	listErr  error
	lastZone *string
}

func (f *fakeS3) ListBuckets(_ context.Context, in *s3.ListBucketsInput, _ ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	f.lastZone = in.BucketRegion
	out := &s3.ListBucketsOutput{}
	for _, b := range f.buckets {
		out.Buckets = append(out.Buckets, s3types.Bucket{Name: aws.String(b)})
	}
	return out, nil
}

func (f *fakeS3) GetPublicAccessBlock(_ context.Context, in *s3.GetPublicAccessBlockInput, _ ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error) {
	name := aws.ToString(in.Bucket)
	if err, ok := f.pabErr[name]; ok {
		return nil, err
	}
	return &s3.GetPublicAccessBlockOutput{PublicAccessBlockConfiguration: f.pab[name]}, nil
}

func (f *fakeS3) GetBucketEncryption(_ context.Context, in *s3.GetBucketEncryptionInput, _ ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error) {
	name := aws.ToString(in.Bucket)
	if err, ok := f.encErr[name]; ok {
		return nil, err
	}
	algo, ok := f.encAlgo[name]
	if !ok {
		return &s3.GetBucketEncryptionOutput{}, nil
	}
	return &s3.GetBucketEncryptionOutput{
		ServerSideEncryptionConfiguration: &s3types.ServerSideEncryptionConfiguration{
			Rules: []s3types.ServerSideEncryptionRule{{
				ApplyServerSideEncryptionByDefault: &s3types.ServerSideEncryptionByDefault{
					SSEAlgorithm: s3types.ServerSideEncryption(algo),
				},
			}},
		},
	}, nil
}

type fakeS3Control struct {
	cfg *s3ctypes.PublicAccessBlockConfiguration
	err error
}

func (f fakeS3Control) GetPublicAccessBlock(context.Context, *s3control.GetPublicAccessBlockInput, ...func(*s3control.Options)) (*s3control.GetPublicAccessBlockOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &s3control.GetPublicAccessBlockOutput{PublicAccessBlockConfiguration: f.cfg}, nil
}

type fakeCloudTrail struct {
	trails []cttypes.Trail
	err    error
}

func (f fakeCloudTrail) DescribeTrails(context.Context, *cloudtrail.DescribeTrailsInput, ...func(*cloudtrail.Options)) (*cloudtrail.DescribeTrailsOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &cloudtrail.DescribeTrailsOutput{TrailList: f.trails}, nil
}

// --- ヘルパ ---

func runCheck(t *testing.T, id string, c *Clients) []Result {
	t.Helper()
	check, ok := ChecksByID()[id]
	if !ok {
		t.Fatalf("チェック %q が定義に無い", id)
	}
	return check.Run(context.Background(), c)
}

func onlyResult(t *testing.T, res []Result) Result {
	t.Helper()
	if len(res) != 1 {
		t.Fatalf("結果が %d 件、want 1: %+v", len(res), res)
	}
	return res[0]
}

func baseClients() *Clients {
	return &Clients{AccountID: "123456789012", Region: "ap-northeast-1"}
}

// --- IAM ---

func TestRootMFA(t *testing.T) {
	for _, tc := range []struct {
		name    string
		summary map[string]int32
		err     error
		want    Status
	}{
		{"MFA 有効", map[string]int32{"AccountMFAEnabled": 1}, nil, StatusPass},
		{"MFA 無効", map[string]int32{"AccountMFAEnabled": 0}, nil, StatusFail},
		// サマリにキーが無い / API が失敗した場合を fail にすると、
		// 一時的な障害が「ルート MFA が無効」という重大所見になる。
		{"キーが無い", map[string]int32{}, nil, StatusUnknown},
		{"API エラー", nil, errors.New("AccessDenied"), StatusUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := baseClients()
			c.IAM = fakeIAM{summary: tc.summary, err: tc.err}
			got := onlyResult(t, runCheck(t, "aws-iam-root-mfa", c))
			if got.Status != tc.want {
				t.Errorf("status = %q, want %q (evidence: %s)", got.Status, tc.want, got.Evidence)
			}
		})
	}
}

func TestRootAccessKeys(t *testing.T) {
	c := baseClients()
	c.IAM = fakeIAM{summary: map[string]int32{"AccountAccessKeysPresent": 1}}
	if got := onlyResult(t, runCheck(t, "aws-iam-root-access-key", c)); got.Status != StatusFail {
		t.Errorf("キーが存在するのに %q", got.Status)
	}

	c.IAM = fakeIAM{summary: map[string]int32{"AccountAccessKeysPresent": 0}}
	if got := onlyResult(t, runCheck(t, "aws-iam-root-access-key", c)); got.Status != StatusPass {
		t.Errorf("キーが無いのに %q", got.Status)
	}
}

func TestPasswordPolicy(t *testing.T) {
	// ポリシー未設定は「読めなかった」ではなく「設定されていない」= fail。
	c := baseClients()
	c.IAM = fakeIAM{noPolicy: true}
	got := onlyResult(t, runCheck(t, "aws-iam-password-min-length", c))
	if got.Status != StatusFail {
		t.Errorf("ポリシー未設定で status = %q, want fail", got.Status)
	}

	c.IAM = fakeIAM{policy: &iamtypes.PasswordPolicy{
		MinimumPasswordLength:   aws.Int32(8),
		PasswordReusePrevention: aws.Int32(24),
	}}
	if got := onlyResult(t, runCheck(t, "aws-iam-password-min-length", c)); got.Status != StatusFail {
		t.Errorf("8 文字で status = %q, want fail", got.Status)
	}
	if got := onlyResult(t, runCheck(t, "aws-iam-password-reuse-prevention", c)); got.Status != StatusPass {
		t.Errorf("再利用防止 24 で status = %q, want pass", got.Status)
	}

	c.IAM = fakeIAM{policy: &iamtypes.PasswordPolicy{
		MinimumPasswordLength: aws.Int32(14),
	}}
	if got := onlyResult(t, runCheck(t, "aws-iam-password-min-length", c)); got.Status != StatusPass {
		t.Errorf("14 文字で status = %q, want pass", got.Status)
	}
	// PasswordReusePrevention が nil のときは 0 扱いで fail。
	if got := onlyResult(t, runCheck(t, "aws-iam-password-reuse-prevention", c)); got.Status != StatusFail {
		t.Errorf("再利用防止 未設定で status = %q, want fail", got.Status)
	}
}

// --- セキュリティグループ ---

func sg(id, name string, perms ...ec2types.IpPermission) ec2types.SecurityGroup {
	return ec2types.SecurityGroup{
		GroupId: aws.String(id), GroupName: aws.String(name), IpPermissions: perms,
	}
}

func tcpRange(from, to int32, cidr string) ec2types.IpPermission {
	return ec2types.IpPermission{
		IpProtocol: aws.String("tcp"),
		FromPort:   aws.Int32(from), ToPort: aws.Int32(to),
		IpRanges: []ec2types.IpRange{{CidrIp: aws.String(cidr)}},
	}
}

func TestSecurityGroupSSHOpen(t *testing.T) {
	for _, tc := range []struct {
		name string
		perm ec2types.IpPermission
		want Status
	}{
		{"22 番が全世界公開", tcpRange(22, 22, "0.0.0.0/0"), StatusFail},
		{"22 番だが社内 IP のみ", tcpRange(22, 22, "203.0.113.0/24"), StatusPass},
		// 範囲で 22 を含む場合も検出できないと、20-30 のような
		// まとめ開放を見逃す。
		{"20-30 の範囲に 22 が含まれる", tcpRange(20, 30, "0.0.0.0/0"), StatusFail},
		{"22 を含まない範囲", tcpRange(80, 443, "0.0.0.0/0"), StatusPass},
		{
			"全プロトコル許可",
			ec2types.IpPermission{
				IpProtocol: aws.String("-1"),
				IpRanges:   []ec2types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}},
			},
			StatusFail,
		},
		{
			"IPv6 の全世界公開",
			ec2types.IpPermission{
				IpProtocol: aws.String("tcp"),
				FromPort:   aws.Int32(22), ToPort: aws.Int32(22),
				Ipv6Ranges: []ec2types.Ipv6Range{{CidrIpv6: aws.String("::/0")}},
			},
			StatusFail,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := baseClients()
			c.EC2 = &fakeEC2{groups: []ec2types.SecurityGroup{sg("sg-1", "web", tc.perm)}}
			got := onlyResult(t, runCheck(t, "aws-ec2-sg-ssh-open", c))
			if got.Status != tc.want {
				t.Errorf("status = %q, want %q (evidence: %s)", got.Status, tc.want, got.Evidence)
			}
			if got.ResourceID != "sg-1" {
				t.Errorf("resource_id = %q, want sg-1 (所見を資源に紐付けられない)", got.ResourceID)
			}
		})
	}
}

// セキュリティグループが複数ページに渡る場合に、2 ページ目を取り逃がさないこと。
// 取りこぼすと「見えていない資源は問題なし」になる。
func TestSecurityGroupsPaginate(t *testing.T) {
	c := baseClients()
	c.EC2 = &fakeEC2{groups: []ec2types.SecurityGroup{
		sg("sg-1", "web", tcpRange(80, 80, "0.0.0.0/0")),
		sg("sg-2", "admin", tcpRange(3389, 3389, "0.0.0.0/0")),
	}}
	res := runCheck(t, "aws-ec2-sg-rdp-open", c)
	if len(res) != 2 {
		t.Fatalf("結果が %d 件、want 2 (2 ページ目を辿れていない)", len(res))
	}
	found := false
	for _, r := range res {
		if r.ResourceID == "sg-2" && r.Status == StatusFail {
			found = true
		}
	}
	if !found {
		t.Error("2 ページ目の sg-2 の RDP 全世界公開を検出できていない")
	}
}

func TestDefaultSecurityGroupRestricted(t *testing.T) {
	c := baseClients()
	// default 以外は対象外。
	c.EC2 = &fakeEC2{groups: []ec2types.SecurityGroup{
		sg("sg-1", "web", tcpRange(80, 80, "0.0.0.0/0")),
		sg("sg-2", "default"),
	}}
	res := runCheck(t, "aws-ec2-default-sg-restricted", c)
	got := onlyResult(t, res)
	if got.ResourceID != "sg-2" {
		t.Fatalf("resource_id = %q, want sg-2 (default 以外を見ている)", got.ResourceID)
	}
	if got.Status != StatusPass {
		t.Errorf("規則が無い default で status = %q, want pass", got.Status)
	}

	c.EC2 = &fakeEC2{groups: []ec2types.SecurityGroup{
		sg("sg-2", "default", tcpRange(0, 65535, "10.0.0.0/8")),
	}}
	if got := onlyResult(t, runCheck(t, "aws-ec2-default-sg-restricted", c)); got.Status != StatusFail {
		t.Errorf("規則が残る default で status = %q, want fail", got.Status)
	}
}

func TestEBSDefaultEncryption(t *testing.T) {
	c := baseClients()
	c.EC2 = &fakeEC2{ebsByDef: true}
	if got := onlyResult(t, runCheck(t, "aws-ec2-ebs-default-encryption", c)); got.Status != StatusPass {
		t.Errorf("既定暗号化 有効で status = %q", got.Status)
	}
	c.EC2 = &fakeEC2{ebsByDef: false}
	if got := onlyResult(t, runCheck(t, "aws-ec2-ebs-default-encryption", c)); got.Status != StatusFail {
		t.Errorf("既定暗号化 無効で status = %q", got.Status)
	}
	c.EC2 = &fakeEC2{err: errors.New("AccessDenied")}
	if got := onlyResult(t, runCheck(t, "aws-ec2-ebs-default-encryption", c)); got.Status != StatusUnknown {
		t.Errorf("API エラーで status = %q, want unknown", got.Status)
	}
}

// --- S3 ---

func allBlocked() *s3types.PublicAccessBlockConfiguration {
	return &s3types.PublicAccessBlockConfiguration{
		BlockPublicAcls: aws.Bool(true), IgnorePublicAcls: aws.Bool(true),
		BlockPublicPolicy: aws.Bool(true), RestrictPublicBuckets: aws.Bool(true),
	}
}

func TestBucketPublicAccessBlock(t *testing.T) {
	partial := allBlocked()
	partial.RestrictPublicBuckets = aws.Bool(false)

	c := baseClients()
	c.S3 = &fakeS3{
		buckets: []string{"ok-bucket", "partial-bucket", "none-bucket", "err-bucket"},
		pab: map[string]*s3types.PublicAccessBlockConfiguration{
			"ok-bucket":      allBlocked(),
			"partial-bucket": partial,
		},
		pabErr: map[string]error{
			"none-bucket": errors.New("NoSuchPublicAccessBlockConfiguration: not found"),
			"err-bucket":  errors.New("AccessDenied"),
		},
	}

	byRes := map[string]Result{}
	for _, r := range runCheck(t, "aws-s3-bucket-public-access-block", c) {
		byRes[r.ResourceID] = r
	}
	if len(byRes) != 4 {
		t.Fatalf("結果が %d 件、want 4", len(byRes))
	}
	for name, want := range map[string]Status{
		"ok-bucket":      StatusPass,
		"partial-bucket": StatusFail,
		"none-bucket":    StatusFail,
		// 権限不足で読めなかったバケットを pass にすると、
		// 公開されていても「問題なし」になる。
		"err-bucket": StatusUnknown,
	} {
		if got := byRes[name].Status; got != want {
			t.Errorf("%s = %q, want %q (evidence: %s)", name, got, want, byRes[name].Evidence)
		}
	}

	// リージョンで絞って一覧しないと、別リージョンのバケットに対して
	// 呼び出してリダイレクトエラーになる。
	if f := c.S3.(*fakeS3); aws.ToString(f.lastZone) != "ap-northeast-1" {
		t.Errorf("ListBuckets の BucketRegion = %q, want ap-northeast-1", aws.ToString(f.lastZone))
	}
}

func TestBucketEncryption(t *testing.T) {
	c := baseClients()
	c.S3 = &fakeS3{
		buckets: []string{"enc", "plain"},
		encAlgo: map[string]string{"enc": "AES256"},
		encErr: map[string]error{
			"plain": errors.New("ServerSideEncryptionConfigurationNotFoundError: none"),
		},
	}
	byRes := map[string]Result{}
	for _, r := range runCheck(t, "aws-s3-bucket-encryption", c) {
		byRes[r.ResourceID] = r
	}
	if byRes["enc"].Status != StatusPass {
		t.Errorf("暗号化済みバケットが %q", byRes["enc"].Status)
	}
	if byRes["plain"].Status != StatusFail {
		t.Errorf("未暗号化バケットが %q", byRes["plain"].Status)
	}
}

func TestAccountPublicAccessBlock(t *testing.T) {
	c := baseClients()
	c.S3Control = fakeS3Control{cfg: &s3ctypes.PublicAccessBlockConfiguration{
		BlockPublicAcls: aws.Bool(true), IgnorePublicAcls: aws.Bool(true),
		BlockPublicPolicy: aws.Bool(true), RestrictPublicBuckets: aws.Bool(true),
	}}
	if got := onlyResult(t, runCheck(t, "aws-s3-account-public-access-block", c)); got.Status != StatusPass {
		t.Errorf("4 項目有効で status = %q", got.Status)
	}

	c.S3Control = fakeS3Control{err: errors.New("NoSuchPublicAccessBlockConfiguration")}
	if got := onlyResult(t, runCheck(t, "aws-s3-account-public-access-block", c)); got.Status != StatusFail {
		t.Errorf("未設定で status = %q, want fail", got.Status)
	}

	c.S3Control = fakeS3Control{err: errors.New("AccessDenied")}
	if got := onlyResult(t, runCheck(t, "aws-s3-account-public-access-block", c)); got.Status != StatusUnknown {
		t.Errorf("権限不足で status = %q, want unknown", got.Status)
	}
}

// --- CloudTrail ---

// 全リージョン証跡が複数あり、検証ありと検証なしが混在する場合。
//
// 実アカウント (検証環境) がまさにこの構成だった。1 本目で打ち切る実装だと
// DescribeTrails の返却順で pass にも fail にもなる。順序は保証されないので、
// 同じ環境をスキャンするたびに結果が変わり得た。
func TestCloudTrailMixedTrailsIsOrderIndependent(t *testing.T) {
	validated := cttypes.Trail{
		Name: aws.String("gpt-cloudtail"), IsMultiRegionTrail: aws.Bool(true),
		LogFileValidationEnabled: aws.Bool(true),
	}
	plain := cttypes.Trail{
		Name: aws.String("management-events"), IsMultiRegionTrail: aws.Bool(true),
		LogFileValidationEnabled: aws.Bool(false),
	}

	for _, tc := range []struct {
		name   string
		trails []cttypes.Trail
	}{
		{"検証ありが先", []cttypes.Trail{validated, plain}},
		{"検証なしが先", []cttypes.Trail{plain, validated}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := baseClients()
			c.CloudTrail = fakeCloudTrail{trails: tc.trails}
			got := onlyResult(t, runCheck(t, "aws-cloudtrail-multiregion", c))
			if got.Status != StatusPass {
				t.Errorf("status = %q, want pass (検証つきの全リージョン証跡が 1 本ある)", got.Status)
			}
			// 検証が無効な証跡が残っていることも運用者に伝える。
			if !strings.Contains(got.Evidence, "management-events") {
				t.Errorf("evidence に検証無効の証跡が出ていない: %s", got.Evidence)
			}
		})
	}
}

// 所見の同一性はアカウントで取る。証跡名を resource_id にすると、
// 証跡が増減しただけで別の所見として作り直されてしまう。
func TestCloudTrailFindingIsAccountScoped(t *testing.T) {
	c := baseClients()
	c.CloudTrail = fakeCloudTrail{trails: []cttypes.Trail{{
		Name: aws.String("only"), IsMultiRegionTrail: aws.Bool(true),
		LogFileValidationEnabled: aws.Bool(false),
	}}}
	got := onlyResult(t, runCheck(t, "aws-cloudtrail-multiregion", c))
	if got.ResourceID != c.AccountID {
		t.Errorf("resource_id = %q, want %q (アカウント単位の項目)", got.ResourceID, c.AccountID)
	}
}

// IncludeShadowTrails=true は他リージョンから見た写しも返す。
// 同じ証跡を二重に数えない。
func TestCloudTrailDeduplicatesShadowCopies(t *testing.T) {
	shadow := cttypes.Trail{
		Name: aws.String("dup"), IsMultiRegionTrail: aws.Bool(true),
		LogFileValidationEnabled: aws.Bool(false),
	}
	c := baseClients()
	c.CloudTrail = fakeCloudTrail{trails: []cttypes.Trail{shadow, shadow, shadow}}
	got := onlyResult(t, runCheck(t, "aws-cloudtrail-multiregion", c))
	if got.Status != StatusFail {
		t.Fatalf("status = %q, want fail", got.Status)
	}
	if n := strings.Count(got.Evidence, "dup"); n != 1 {
		t.Errorf("evidence に dup が %d 回出ている, want 1: %s", n, got.Evidence)
	}
}

func TestCloudTrailMultiRegion(t *testing.T) {
	c := baseClients()

	// 単一リージョンの証跡しか無い場合は不合格。
	c.CloudTrail = fakeCloudTrail{trails: []cttypes.Trail{{
		Name: aws.String("single"), IsMultiRegionTrail: aws.Bool(false),
	}}}
	if got := onlyResult(t, runCheck(t, "aws-cloudtrail-multiregion", c)); got.Status != StatusFail {
		t.Errorf("単一リージョン証跡のみで status = %q, want fail", got.Status)
	}

	// 全リージョン証跡はあるが検証が無効。
	c.CloudTrail = fakeCloudTrail{trails: []cttypes.Trail{{
		Name: aws.String("all"), IsMultiRegionTrail: aws.Bool(true),
		LogFileValidationEnabled: aws.Bool(false),
	}}}
	got := onlyResult(t, runCheck(t, "aws-cloudtrail-multiregion", c))
	if got.Status != StatusFail {
		t.Errorf("ログ検証が無効で status = %q, want fail", got.Status)
	}

	c.CloudTrail = fakeCloudTrail{trails: []cttypes.Trail{{
		Name: aws.String("all"), IsMultiRegionTrail: aws.Bool(true),
		LogFileValidationEnabled: aws.Bool(true),
	}}}
	if got := onlyResult(t, runCheck(t, "aws-cloudtrail-multiregion", c)); got.Status != StatusPass {
		t.Errorf("全リージョン証跡ありで status = %q, want pass", got.Status)
	}
}

// --- 定義そのものの健全性 ---

// check ID は cspm_findings.check_id になり所見の同一性に使う。
// 重複していると別の問題が同じ所見に統合されて消える。
func TestCheckIDsAreUniqueAndComplete(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range Checks() {
		if c.ID == "" {
			t.Errorf("ID が空のチェックがある: %s", c.Title)
		}
		if seen[c.ID] {
			t.Errorf("check ID が重複している: %s", c.ID)
		}
		seen[c.ID] = true

		if c.Run == nil {
			t.Errorf("%s: Run が nil", c.ID)
		}
		// 是正手順の無い所見は、担当者が受け取っても動けない。
		if c.Remediation == "" {
			t.Errorf("%s: Remediation が空", c.ID)
		}
		switch c.Severity {
		case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow:
		default:
			t.Errorf("%s: severity が不正 (%q) — cspm_findings の CHECK 制約に落ちる", c.ID, c.Severity)
		}
		switch c.Scope {
		case ScopeAccount, ScopeRegion:
		default:
			t.Errorf("%s: scope が不正 (%q)", c.ID, c.Scope)
		}
	}
}

// unknown が所見に混ざらず、理由付きで Errors に落ちること。
//
// unknown を Results に入れると Persist が fail として所見にするか
// pass として既存の所見を閉じてしまう。どちらも「読めなかった」を
// 「読めた」に化けさせる。逆に理由を落とすと、権限不足なのか応答の
// 読み方が違うのかを切り分けられない。
func TestRunOneSeparatesUnknownFromFindings(t *testing.T) {
	s := NewScanner()
	res := &ScanResult{}
	c := baseClients()

	check := Check{
		ID: "itest-mixed", Scope: ScopeRegion,
		Run: func(context.Context, *Clients) []Result {
			return []Result{
				{CheckID: "itest-mixed", Status: StatusFail, ResourceID: "r1", Evidence: "だめ"},
				{CheckID: "itest-mixed", Status: StatusPass, ResourceID: "r2", Evidence: "よし"},
				{CheckID: "itest-mixed", Status: StatusUnknown, ResourceID: "r3",
					Region: "ap-northeast-1", Evidence: "AccessDenied"},
			}
		},
	}
	s.runOne(context.Background(), check, c, res, &sync.Mutex{})

	if len(res.Results) != 2 {
		t.Errorf("Results = %d 件, want 2 (unknown が混ざっている)", len(res.Results))
	}
	for _, r := range res.Results {
		if r.Status == StatusUnknown {
			t.Errorf("unknown が Results に入っている: %+v", r)
		}
	}
	if len(res.Errors) != 1 {
		t.Fatalf("Errors = %d 件, want 1", len(res.Errors))
	}
	if res.Errors[0].Message != "AccessDenied" {
		t.Errorf("理由 = %q, want AccessDenied (切り分けができない)", res.Errors[0].Message)
	}
	if res.Errors[0].CheckID != "itest-mixed" || res.Errors[0].Region != "ap-northeast-1" {
		t.Errorf("どのチェック・どのリージョンか分からない: %+v", res.Errors[0])
	}
}

// パニックしたチェックがスキャン全体を落とさず、その項目だけ
// 「検査できなかった」になること。
func TestRunOneContainsPanic(t *testing.T) {
	s := NewScanner()
	res := &ScanResult{}

	check := Check{
		ID: "itest-panic", Scope: ScopeAccount,
		Run: func(context.Context, *Clients) []Result { panic("boom") },
	}
	s.runOne(context.Background(), check, baseClients(), res, &sync.Mutex{})

	if len(res.Results) != 0 {
		t.Errorf("パニックしたのに所見が %d 件できている", len(res.Results))
	}
	if len(res.Errors) != 1 || res.Errors[0].CheckID != "itest-panic" {
		t.Errorf("パニックが記録されていない: %+v", res.Errors)
	}
}
