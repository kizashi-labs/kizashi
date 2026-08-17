package awsscan

// 検査項目。CIS AWS Foundations Benchmark の項番に寄せてある。
//
// 選定方針: SOC 人員が薄い組織で「入れた直後に効く」ものを優先した。
// ルート権限・公開・暗号化・監査ログの 4 系統に絞り、資源を 1 件ずつ
// 舐める必要があるもの (認証情報レポート、IAM ポリシー全走査など) は
// 第 2 弾に回している。項目の追加はこのファイルへの追記だけで済む。
//
// check ID は cspm_findings.check_id になり所見の同一性に使うので、
// 一度出したら変えない。変えると同じ問題が別の所見として増える。

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
)

// Checks は実行する項目の一覧。
func Checks() []Check {
	return []Check{
		checkRootMFA(),
		checkRootAccessKeys(),
		checkPasswordPolicyLength(),
		checkPasswordReusePrevention(),
		checkAccountPublicAccessBlock(),
		checkCloudTrailMultiRegion(),
		checkBucketPublicAccessBlock(),
		checkBucketEncryption(),
		checkSecurityGroupPort(22, "SSH", "aws-ec2-sg-ssh-open"),
		checkSecurityGroupPort(3389, "RDP", "aws-ec2-sg-rdp-open"),
		checkDefaultSecurityGroupRestricted(),
		checkEBSDefaultEncryption(),
	}
}

// ChecksByID は Checks() を ID 引きにしたもの。
func ChecksByID() map[string]Check {
	out := map[string]Check{}
	for _, c := range Checks() {
		out[c.ID] = c
	}
	return out
}

// --- IAM (アカウント単位) ---

// accountSummary は GetAccountSummary の数値マップを引く。
// 該当キーが無い場合があるので、存在有無を返す。
func accountSummary(ctx context.Context, c *Clients) (map[string]int32, error) {
	out, err := c.IAM.GetAccountSummary(ctx, &iam.GetAccountSummaryInput{})
	if err != nil {
		return nil, err
	}
	m := map[string]int32{}
	for k, v := range out.SummaryMap {
		m[k] = v
	}
	return m, nil
}

func checkRootMFA() Check {
	return Check{
		ID:          "aws-iam-root-mfa",
		Title:       "ルートアカウントで MFA が有効",
		Description: "ルートユーザーは全操作が可能なため、MFA なしの状態はパスワード漏洩がそのままアカウント全体の掌握につながる。",
		Severity:    SeverityCritical,
		Scope:       ScopeAccount,
		Service:     "IAM",
		Frameworks:  []string{"CIS-AWS-1.5"},
		Remediation: "ルートユーザーでサインインし、IAM > セキュリティ認証情報から MFA デバイスを割り当ててください。",
		Run: func(ctx context.Context, c *Clients) []Result {
			sum, err := accountSummary(ctx, c)
			if err != nil {
				return unknownOne("aws-iam-root-mfa", c, "アカウントサマリの取得に失敗: "+err.Error())
			}
			v, ok := sum["AccountMFAEnabled"]
			if !ok {
				return unknownOne("aws-iam-root-mfa", c, "AccountMFAEnabled がサマリに含まれていません")
			}
			if v == 1 {
				return passOne("aws-iam-root-mfa", c, "ルートアカウントの MFA は有効です")
			}
			return failOne("aws-iam-root-mfa", c, "ルートアカウントの MFA が無効です")
		},
	}
}

func checkRootAccessKeys() Check {
	return Check{
		ID:          "aws-iam-root-access-key",
		Title:       "ルートアカウントのアクセスキーが存在しない",
		Description: "ルートのアクセスキーは失効も権限の絞り込みもできず、漏洩時の影響が最大になる。",
		Severity:    SeverityCritical,
		Scope:       ScopeAccount,
		Service:     "IAM",
		Frameworks:  []string{"CIS-AWS-1.4"},
		Remediation: "IAM > セキュリティ認証情報からルートのアクセスキーを削除し、用途ごとに IAM ユーザーまたはロールへ置き換えてください。",
		Run: func(ctx context.Context, c *Clients) []Result {
			sum, err := accountSummary(ctx, c)
			if err != nil {
				return unknownOne("aws-iam-root-access-key", c, "アカウントサマリの取得に失敗: "+err.Error())
			}
			v, ok := sum["AccountAccessKeysPresent"]
			if !ok {
				return unknownOne("aws-iam-root-access-key", c, "AccountAccessKeysPresent がサマリに含まれていません")
			}
			if v == 0 {
				return passOne("aws-iam-root-access-key", c, "ルートのアクセスキーはありません")
			}
			return failOne("aws-iam-root-access-key", c, "ルートのアクセスキーが存在します")
		},
	}
}

// passwordPolicy はパスワードポリシーを引く。未設定は「エラー」ではなく
// 「ポリシーが無い」として扱う。
func passwordPolicy(ctx context.Context, c *Clients) (*iamtypes.PasswordPolicy, bool, error) {
	out, err := c.IAM.GetAccountPasswordPolicy(ctx, &iam.GetAccountPasswordPolicyInput{})
	if err != nil {
		var notFound *iamtypes.NoSuchEntityException
		if errors.As(err, &notFound) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return out.PasswordPolicy, true, nil
}

func checkPasswordPolicyLength() Check {
	const id = "aws-iam-password-min-length"
	return Check{
		ID:          id,
		Title:       "IAM パスワードポリシーの最小長が 14 文字以上",
		Description: "短いパスワードは総当たりに耐えない。",
		Severity:    SeverityMedium,
		Scope:       ScopeAccount,
		Service:     "IAM",
		Frameworks:  []string{"CIS-AWS-1.8"},
		Remediation: "IAM > アカウント設定でパスワードポリシーの最小長を 14 文字以上に設定してください。",
		Run: func(ctx context.Context, c *Clients) []Result {
			pp, exists, err := passwordPolicy(ctx, c)
			if err != nil {
				return unknownOne(id, c, "パスワードポリシーの取得に失敗: "+err.Error())
			}
			if !exists {
				return failOne(id, c, "パスワードポリシーが設定されていません")
			}
			n := int32(0)
			if pp.MinimumPasswordLength != nil {
				n = *pp.MinimumPasswordLength
			}
			if n >= 14 {
				return passOne(id, c, fmt.Sprintf("最小長 %d 文字", n))
			}
			return failOne(id, c, fmt.Sprintf("最小長が %d 文字です (14 文字以上が必要)", n))
		},
	}
}

func checkPasswordReusePrevention() Check {
	const id = "aws-iam-password-reuse-prevention"
	return Check{
		ID:          id,
		Title:       "IAM パスワードの再利用を 24 世代分禁止",
		Description: "同じパスワードへの戻しを許すと、定期変更が実質的に無意味になる。",
		Severity:    SeverityLow,
		Scope:       ScopeAccount,
		Service:     "IAM",
		Frameworks:  []string{"CIS-AWS-1.9"},
		Remediation: "IAM > アカウント設定でパスワードの再利用防止を 24 に設定してください。",
		Run: func(ctx context.Context, c *Clients) []Result {
			pp, exists, err := passwordPolicy(ctx, c)
			if err != nil {
				return unknownOne(id, c, "パスワードポリシーの取得に失敗: "+err.Error())
			}
			if !exists {
				return failOne(id, c, "パスワードポリシーが設定されていません")
			}
			n := int32(0)
			if pp.PasswordReusePrevention != nil {
				n = *pp.PasswordReusePrevention
			}
			if n >= 24 {
				return passOne(id, c, fmt.Sprintf("再利用防止 %d 世代", n))
			}
			return failOne(id, c, fmt.Sprintf("再利用防止が %d 世代です (24 以上が必要)", n))
		},
	}
}

// --- S3 ---

func checkAccountPublicAccessBlock() Check {
	const id = "aws-s3-account-public-access-block"
	return Check{
		ID:          id,
		Title:       "S3 のアカウント全体のパブリックアクセスブロックが有効",
		Description: "アカウント単位でブロックしておくと、個別バケットの設定ミスが公開に直結しなくなる。",
		Severity:    SeverityHigh,
		Scope:       ScopeAccount,
		Service:     "S3",
		Frameworks:  []string{"CIS-AWS-2.1.4"},
		Remediation: "S3 コンソール > このアカウントのブロックパブリックアクセス設定で 4 項目すべてを有効にしてください。",
		Run: func(ctx context.Context, c *Clients) []Result {
			out, err := c.S3Control.GetPublicAccessBlock(ctx, &s3control.GetPublicAccessBlockInput{
				AccountId: aws.String(c.AccountID),
			})
			if err != nil {
				// 未設定時は NoSuchPublicAccessBlockConfiguration が返る。
				// 型が公開されていないのでメッセージで判別する。
				if strings.Contains(err.Error(), "NoSuchPublicAccessBlockConfiguration") {
					return failOne(id, c, "アカウント全体のパブリックアクセスブロックが未設定です")
				}
				return unknownOne(id, c, "取得に失敗: "+err.Error())
			}
			cfg := out.PublicAccessBlockConfiguration
			if cfg == nil {
				return failOne(id, c, "パブリックアクセスブロックの設定が空です")
			}
			if missing := publicAccessGaps(cfg.BlockPublicAcls, cfg.IgnorePublicAcls,
				cfg.BlockPublicPolicy, cfg.RestrictPublicBuckets); len(missing) > 0 {
				return failOne(id, c, "無効な項目: "+strings.Join(missing, ", "))
			}
			return passOne(id, c, "4 項目すべて有効です")
		},
	}
}

// publicAccessGaps は 4 項目のうち有効になっていないものの名前を返す。
func publicAccessGaps(blockACL, ignoreACL, blockPolicy, restrict *bool) []string {
	var missing []string
	for _, f := range []struct {
		name string
		v    *bool
	}{
		{"BlockPublicAcls", blockACL},
		{"IgnorePublicAcls", ignoreACL},
		{"BlockPublicPolicy", blockPolicy},
		{"RestrictPublicBuckets", restrict},
	} {
		if !aws.ToBool(f.v) {
			missing = append(missing, f.name)
		}
	}
	return missing
}

// regionBuckets はこのリージョンにあるバケットを列挙する。
// BucketRegion で絞ることで、リージョン跨ぎの呼び出し
// (PermanentRedirect) を避ける。
func regionBuckets(ctx context.Context, c *Clients) ([]s3types.Bucket, error) {
	out, err := c.S3.ListBuckets(ctx, &s3.ListBucketsInput{
		BucketRegion: aws.String(c.Region),
	})
	if err != nil {
		return nil, err
	}
	return out.Buckets, nil
}

func checkBucketPublicAccessBlock() Check {
	const id = "aws-s3-bucket-public-access-block"
	return Check{
		ID:          id,
		Title:       "S3 バケットのパブリックアクセスブロックが有効",
		Description: "バケット単位のブロックが無いと、ACL やバケットポリシーの設定ミスがそのまま公開になる。",
		Severity:    SeverityCritical,
		Scope:       ScopeRegion,
		Service:     "S3",
		Frameworks:  []string{"CIS-AWS-2.1.4"},
		Remediation: "対象バケットのアクセス許可タブで、ブロックパブリックアクセスの 4 項目を有効にしてください。",
		Run: func(ctx context.Context, c *Clients) []Result {
			buckets, err := regionBuckets(ctx, c)
			if err != nil {
				return unknownOne(id, c, "バケット一覧の取得に失敗: "+err.Error())
			}
			var out []Result
			for _, b := range buckets {
				name := aws.ToString(b.Name)
				res := Result{
					CheckID: id, ResourceID: name, ResourceName: name,
					ResourceType: "AwsS3Bucket", Region: c.Region,
				}
				pab, err := c.S3.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{
					Bucket: aws.String(name),
				})
				switch {
				case err != nil && strings.Contains(err.Error(), "NoSuchPublicAccessBlockConfiguration"):
					res.Status, res.Evidence = StatusFail, "パブリックアクセスブロックが未設定です"
				case err != nil:
					res.Status, res.Evidence = StatusUnknown, "取得に失敗: "+err.Error()
				case pab.PublicAccessBlockConfiguration == nil:
					res.Status, res.Evidence = StatusFail, "パブリックアクセスブロックの設定が空です"
				default:
					cfg := pab.PublicAccessBlockConfiguration
					missing := publicAccessGaps(cfg.BlockPublicAcls, cfg.IgnorePublicAcls,
						cfg.BlockPublicPolicy, cfg.RestrictPublicBuckets)
					if len(missing) > 0 {
						res.Status, res.Evidence = StatusFail, "無効な項目: "+strings.Join(missing, ", ")
					} else {
						res.Status, res.Evidence = StatusPass, "4 項目すべて有効です"
					}
				}
				out = append(out, res)
			}
			return out
		},
	}
}

func checkBucketEncryption() Check {
	const id = "aws-s3-bucket-encryption"
	return Check{
		ID:          id,
		Title:       "S3 バケットの既定の暗号化が有効",
		Description: "既定の暗号化が無いバケットは、書き込み側が指定しない限り平文で保存される。",
		Severity:    SeverityMedium,
		Scope:       ScopeRegion,
		Service:     "S3",
		Frameworks:  []string{"CIS-AWS-2.1.1"},
		Remediation: "対象バケットのプロパティタブで、デフォルトの暗号化 (SSE-S3 または SSE-KMS) を有効にしてください。",
		Run: func(ctx context.Context, c *Clients) []Result {
			buckets, err := regionBuckets(ctx, c)
			if err != nil {
				return unknownOne(id, c, "バケット一覧の取得に失敗: "+err.Error())
			}
			var out []Result
			for _, b := range buckets {
				name := aws.ToString(b.Name)
				res := Result{
					CheckID: id, ResourceID: name, ResourceName: name,
					ResourceType: "AwsS3Bucket", Region: c.Region,
				}
				enc, err := c.S3.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{
					Bucket: aws.String(name),
				})
				switch {
				case err != nil && strings.Contains(err.Error(), "ServerSideEncryptionConfigurationNotFoundError"):
					res.Status, res.Evidence = StatusFail, "既定の暗号化が設定されていません"
				case err != nil:
					res.Status, res.Evidence = StatusUnknown, "取得に失敗: "+err.Error()
				case enc.ServerSideEncryptionConfiguration == nil ||
					len(enc.ServerSideEncryptionConfiguration.Rules) == 0:
					res.Status, res.Evidence = StatusFail, "暗号化ルールが空です"
				default:
					algo := "不明"
					if d := enc.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault; d != nil {
						algo = string(d.SSEAlgorithm)
					}
					res.Status, res.Evidence = StatusPass, "既定の暗号化: "+algo
				}
				out = append(out, res)
			}
			return out
		},
	}
}

// --- CloudTrail ---

func checkCloudTrailMultiRegion() Check {
	const id = "aws-cloudtrail-multiregion"
	return Check{
		ID:          id,
		Title:       "全リージョンを対象とする CloudTrail が有効",
		Description: "証跡が無いリージョンでの操作は後から追えない。侵入者が普段使わないリージョンを選ぶのは定石。",
		Severity:    SeverityHigh,
		Scope:       ScopeAccount,
		Service:     "CloudTrail",
		Frameworks:  []string{"CIS-AWS-3.1"},
		Remediation: "CloudTrail で「すべてのリージョンに適用」を有効にした証跡を作成し、ログファイルの検証も有効にしてください。",
		Run: func(ctx context.Context, c *Clients) []Result {
			out, err := c.CloudTrail.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{
				IncludeShadowTrails: aws.Bool(true),
			})
			if err != nil {
				return unknownOne(id, c, "証跡の取得に失敗: "+err.Error())
			}
			// 全リージョン証跡は複数あり得る。1 本目で打ち切ると、
			// 検証ありと検証なしが混在するアカウントで DescribeTrails の
			// 返却順によって pass にも fail にもなる (順序は保証されない)。
			// 「検証付きの全リージョン証跡が 1 本でもあるか」で判定する。
			//
			// IncludeShadowTrails=true は他リージョンから見た写しも返すので、
			// 同じ証跡が複数回現れる。名前で畳む。
			var multiRegion, validated []string
			seen := map[string]bool{}
			for _, t := range out.TrailList {
				if !aws.ToBool(t.IsMultiRegionTrail) {
					continue
				}
				name := aws.ToString(t.Name)
				if name == "" || seen[name] {
					continue
				}
				seen[name] = true
				multiRegion = append(multiRegion, name)
				if aws.ToBool(t.LogFileValidationEnabled) {
					validated = append(validated, name)
				}
			}
			// 証跡が増減しても文言が安定するように並べる。
			sort.Strings(multiRegion)
			sort.Strings(validated)

			switch {
			case len(multiRegion) == 0:
				return failOne(id, c, "全リージョンを対象とする証跡がありません")
			case len(validated) == 0:
				return failOne(id, c, "全リージョン証跡 ("+strings.Join(multiRegion, ", ")+
					") はあるが、ログファイルの検証が有効なものがありません")
			default:
				ev := "全リージョン証跡 " + strings.Join(validated, ", ") + " がログファイル検証つきで有効です"
				if len(validated) < len(multiRegion) {
					ev += " (検証が無効な証跡も存在: " + strings.Join(without(multiRegion, validated), ", ") + ")"
				}
				return passOne(id, c, ev)
			}
		},
	}
}

// --- EC2 (リージョン単位) ---

func checkSecurityGroupPort(port int32, label, id string) Check {
	return Check{
		ID:          id,
		Title:       fmt.Sprintf("%s(%d) が全世界に公開されていない", label, port),
		Description: fmt.Sprintf("0.0.0.0/0 からの %s は総当たりの標的になる。", label),
		Severity:    SeverityHigh,
		Scope:       ScopeRegion,
		Service:     "EC2",
		Frameworks:  []string{"CIS-AWS-5.2"},
		Remediation: fmt.Sprintf("該当セキュリティグループの %d 番ポートの送信元を、必要な IP レンジまたは踏み台のみに限定してください。", port),
		Run: func(ctx context.Context, c *Clients) []Result {
			groups, err := allSecurityGroups(ctx, c)
			if err != nil {
				return unknownOne(id, c, "セキュリティグループの取得に失敗: "+err.Error())
			}
			var out []Result
			for _, g := range groups {
				sgID := aws.ToString(g.GroupId)
				res := Result{
					CheckID: id, ResourceID: sgID,
					ResourceName: aws.ToString(g.GroupName),
					ResourceType: "AwsEc2SecurityGroup", Region: c.Region,
				}
				if src := openToWorldOn(g, port); src != "" {
					res.Status = StatusFail
					res.Evidence = fmt.Sprintf("%d 番が %s に開放されています", port, src)
				} else {
					res.Status = StatusPass
					res.Evidence = fmt.Sprintf("%d 番の全世界公開はありません", port)
				}
				out = append(out, res)
			}
			return out
		},
	}
}

// openToWorldOn は指定ポートが 0.0.0.0/0 か ::/0 に開いていれば、その
// 送信元表記を返す。開いていなければ空文字。
func openToWorldOn(g ec2types.SecurityGroup, port int32) string {
	for _, p := range g.IpPermissions {
		if !portInRange(p, port) {
			continue
		}
		for _, r := range p.IpRanges {
			if aws.ToString(r.CidrIp) == "0.0.0.0/0" {
				return "0.0.0.0/0"
			}
		}
		for _, r := range p.Ipv6Ranges {
			if aws.ToString(r.CidrIpv6) == "::/0" {
				return "::/0"
			}
		}
	}
	return ""
}

// portInRange は許可範囲が指定ポートを含むかを見る。
// FromPort/ToPort が nil の規則は全ポート許可 (プロトコル -1 等) を意味する。
func portInRange(p ec2types.IpPermission, port int32) bool {
	if aws.ToString(p.IpProtocol) == "-1" {
		return true
	}
	if p.FromPort == nil || p.ToPort == nil {
		return false
	}
	return *p.FromPort <= port && port <= *p.ToPort
}

func allSecurityGroups(ctx context.Context, c *Clients) ([]ec2types.SecurityGroup, error) {
	var out []ec2types.SecurityGroup
	var token *string
	for {
		page, err := c.EC2.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{
			NextToken: token,
		})
		if err != nil {
			return nil, err
		}
		out = append(out, page.SecurityGroups...)
		if page.NextToken == nil || *page.NextToken == "" {
			return out, nil
		}
		token = page.NextToken
	}
}

func checkDefaultSecurityGroupRestricted() Check {
	const id = "aws-ec2-default-sg-restricted"
	return Check{
		ID:          id,
		Title:       "既定のセキュリティグループが全通信を遮断",
		Description: "既定のセキュリティグループは明示的に指定しなくても割り当たるため、規則が残っていると意図しない通信を許してしまう。",
		Severity:    SeverityMedium,
		Scope:       ScopeRegion,
		Service:     "EC2",
		Frameworks:  []string{"CIS-AWS-5.4"},
		Remediation: "既定のセキュリティグループのインバウンド・アウトバウンド規則をすべて削除し、用途ごとに別のグループを使ってください。",
		Run: func(ctx context.Context, c *Clients) []Result {
			groups, err := allSecurityGroups(ctx, c)
			if err != nil {
				return unknownOne(id, c, "セキュリティグループの取得に失敗: "+err.Error())
			}
			var out []Result
			for _, g := range groups {
				if aws.ToString(g.GroupName) != "default" {
					continue
				}
				sgID := aws.ToString(g.GroupId)
				res := Result{
					CheckID: id, ResourceID: sgID, ResourceName: "default",
					ResourceType: "AwsEc2SecurityGroup", Region: c.Region,
				}
				in, eg := len(g.IpPermissions), len(g.IpPermissionsEgress)
				if in == 0 && eg == 0 {
					res.Status, res.Evidence = StatusPass, "規則はありません"
				} else {
					res.Status = StatusFail
					res.Evidence = fmt.Sprintf("インバウンド %d 件 / アウトバウンド %d 件の規則が残っています", in, eg)
				}
				out = append(out, res)
			}
			return out
		},
	}
}

func checkEBSDefaultEncryption() Check {
	const id = "aws-ec2-ebs-default-encryption"
	return Check{
		ID:          id,
		Title:       "EBS の既定の暗号化が有効",
		Description: "既定が無効だと、作成時に指定し忘れたボリュームが平文になる。",
		Severity:    SeverityMedium,
		Scope:       ScopeRegion,
		Service:     "EC2",
		Frameworks:  []string{"CIS-AWS-2.2.1"},
		Remediation: "EC2 コンソール > EBS の設定で「デフォルトで暗号化」を有効にしてください (リージョンごとの設定です)。",
		Run: func(ctx context.Context, c *Clients) []Result {
			out, err := c.EC2.GetEbsEncryptionByDefault(ctx, &ec2.GetEbsEncryptionByDefaultInput{})
			if err != nil {
				return unknownOne(id, c, "取得に失敗: "+err.Error())
			}
			res := Result{
				CheckID: id, ResourceID: c.AccountID + "/" + c.Region,
				ResourceName: c.Region, ResourceType: "AwsEc2EbsDefaultEncryption",
				Region: c.Region,
			}
			if aws.ToBool(out.EbsEncryptionByDefault) {
				res.Status, res.Evidence = StatusPass, "既定の暗号化は有効です"
			} else {
				res.Status, res.Evidence = StatusFail, "既定の暗号化が無効です"
			}
			return []Result{res}
		},
	}
}

// without は all から drop に含まれるものを除いた並びを返す。
func without(all, drop []string) []string {
	skip := map[string]bool{}
	for _, d := range drop {
		skip[d] = true
	}
	out := make([]string, 0, len(all))
	for _, a := range all {
		if !skip[a] {
			out = append(out, a)
		}
	}
	return out
}

// --- 結果の組み立て ---

func accountResult(checkID string, c *Clients, status Status, evidence string) []Result {
	return []Result{{
		CheckID:      checkID,
		Status:       status,
		ResourceID:   c.AccountID,
		ResourceName: c.AccountID,
		ResourceType: "AwsAccount",
		Region:       c.Region,
		Evidence:     evidence,
	}}
}

func passOne(id string, c *Clients, ev string) []Result {
	return accountResult(id, c, StatusPass, ev)
}
func failOne(id string, c *Clients, ev string) []Result {
	return accountResult(id, c, StatusFail, ev)
}
func unknownOne(id string, c *Clients, ev string) []Result {
	return accountResult(id, c, StatusUnknown, ev)
}
