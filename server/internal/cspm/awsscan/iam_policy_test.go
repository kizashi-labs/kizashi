package awsscan

// CIS 1.16 の判定。
//
// IAM ポリシー文書は Action / Resource が文字列にも配列にもなる。片方しか
// 扱わない実装は、もう片方の形のポリシーを黙って検査対象から外す ---
// 「所見 0 件」に見えるが、実際には読めていないだけ。実アカウント検証で
// 繰り返し踏んだ形なので、両方を明示的に試す。

import (
	"context"
	"errors"
	"net/url"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

type fakeIAMPolicies struct {
	fakeIAM
	policies []iamtypes.Policy
	docs     map[string]string // ARN → ポリシー文書 (素の JSON)
	listErr  error
	docErr   error
	// listCalls はページングの確認用。
	listCalls *int
	// page2 が非 nil なら 1 ページ目を打ち切って 2 ページ目を返す。
	page2 []iamtypes.Policy
}

func (f fakeIAMPolicies) ListPolicies(_ context.Context, in *iam.ListPoliciesInput, _ ...func(*iam.Options)) (*iam.ListPoliciesOutput, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	if f.listCalls != nil {
		*f.listCalls++
	}
	if f.page2 != nil && in.Marker == nil {
		return &iam.ListPoliciesOutput{
			Policies: f.policies, IsTruncated: true, Marker: aws.String("next"),
		}, nil
	}
	if in.Marker != nil {
		return &iam.ListPoliciesOutput{Policies: f.page2}, nil
	}
	return &iam.ListPoliciesOutput{Policies: f.policies}, nil
}

func (f fakeIAMPolicies) GetPolicyVersion(_ context.Context, in *iam.GetPolicyVersionInput, _ ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error) {
	if f.docErr != nil {
		return nil, f.docErr
	}
	doc, ok := f.docs[aws.ToString(in.PolicyArn)]
	if !ok {
		return nil, errors.New("NoSuchEntity")
	}
	// 実物と同じく URL エンコードして返す。
	return &iam.GetPolicyVersionOutput{
		PolicyVersion: &iamtypes.PolicyVersion{Document: aws.String(url.QueryEscape(doc))},
	}, nil
}

func policyFixture(name, arn string) iamtypes.Policy {
	return iamtypes.Policy{
		PolicyName: aws.String(name), Arn: aws.String(arn),
		DefaultVersionId: aws.String("v1"), AttachmentCount: aws.Int32(1),
	}
}

func TestFullAdminPolicyDetection(t *testing.T) {
	for _, tc := range []struct {
		name string
		doc  string
		want Status
	}{
		{
			// 配列形式。
			"配列の *:* は不合格",
			`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["*"],"Resource":["*"]}]}`,
			StatusFail,
		},
		{
			// 文字列形式。片方しか扱わない実装だとここを取りこぼす。
			"文字列の *:* は不合格",
			`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`,
			StatusFail,
		},
		{
			// 混在。
			"Action が文字列で Resource が配列でも不合格",
			`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":["*"]}]}`,
			StatusFail,
		},
		{
			// 複数文のうち 1 つが *:*。
			"複数文のうち 1 つが *:* なら不合格",
			`{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"},` +
				`{"Effect":"Allow","Action":"*","Resource":"*"}]}`,
			StatusFail,
		},
		{
			// サービス全権は CIS 1.16 の対象外。ここを拾うと正当な運用
			// ポリシーまで high で挙がり、一覧が実務に耐えなくなる。
			"サービス全権 (s3:*) は対象外",
			`{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`,
			StatusPass,
		},
		{
			"Resource が限定されていれば合格",
			`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"arn:aws:s3:::my-bucket/*"}]}`,
			StatusPass,
		},
		{
			// 条件付きは無条件の許可ではない。MFA 必須の管理ロールなどが該当する。
			"Condition 付きは対象外",
			`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*",` +
				`"Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}}]}`,
			StatusPass,
		},
		{
			"Deny は対象外",
			`{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}`,
			StatusPass,
		},
		{
			// NotAction は意味が反転する。誤判定するくらいなら対象外にする。
			"NotAction 付きは対象外",
			`{"Statement":[{"Effect":"Allow","NotAction":"iam:*","Resource":"*"}]}`,
			StatusPass,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const arn = "arn:aws:iam::123456789012:policy/test"
			c := baseClients()
			c.IAM = fakeIAMPolicies{
				policies: []iamtypes.Policy{policyFixture("test", arn)},
				docs:     map[string]string{arn: tc.doc},
			}
			got := onlyResult(t, runCheck(t, "aws-iam-no-full-admin-policy", c))
			if got.Status != tc.want {
				t.Errorf("status = %q, want %q (evidence: %s)", got.Status, tc.want, got.Evidence)
			}
			if got.ResourceID != arn {
				t.Errorf("resource_id = %q, want %q", got.ResourceID, arn)
			}
		})
	}
}

// ポリシーが複数ページに渡る場合に 2 ページ目を取り逃がさないこと。
// 取りこぼすと「見えていないポリシーは問題なし」になる。
func TestIAMPoliciesPaginate(t *testing.T) {
	calls := 0
	const arn1 = "arn:aws:iam::123456789012:policy/p1"
	const arn2 = "arn:aws:iam::123456789012:policy/p2"
	c := baseClients()
	c.IAM = fakeIAMPolicies{
		listCalls: &calls,
		policies:  []iamtypes.Policy{policyFixture("p1", arn1)},
		page2:     []iamtypes.Policy{policyFixture("p2", arn2)},
		docs: map[string]string{
			arn1: `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`,
			arn2: `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`,
		},
	}

	got := runCheck(t, "aws-iam-no-full-admin-policy", c)
	if len(got) != 2 {
		t.Fatalf("結果が %d 件, want 2 (2 ページ目を取り逃がしている): %+v", len(got), got)
	}
	var found bool
	for _, r := range got {
		if r.ResourceID == arn2 {
			found = true
			if r.Status != StatusFail {
				t.Errorf("2 ページ目の *:* が %q, want fail", r.Status)
			}
		}
	}
	if !found {
		t.Error("2 ページ目のポリシーが結果に出ていない")
	}
}

// 1 本のポリシー文書が読めなくても、残りの判定は続けること。
// 全体を unknown にすると、読めた分の本物の所見まで消える。
func TestPolicyDocumentFailureIsPerPolicy(t *testing.T) {
	const arn = "arn:aws:iam::123456789012:policy/unreadable"
	c := baseClients()
	c.IAM = fakeIAMPolicies{
		policies: []iamtypes.Policy{policyFixture("unreadable", arn)},
		docs:     map[string]string{}, // 文書が引けない
	}
	got := onlyResult(t, runCheck(t, "aws-iam-no-full-admin-policy", c))
	if got.Status != StatusUnknown {
		t.Errorf("status = %q, want unknown", got.Status)
	}
}

// 一覧そのものが取れなければ unknown。pass に倒すと
// 「管理者権限の濫用は無い」という最も安心できる表示になる。
func TestPolicyListFailureIsUnknown(t *testing.T) {
	c := baseClients()
	c.IAM = fakeIAMPolicies{listErr: errAccessDenied{}}
	got := onlyResult(t, runCheck(t, "aws-iam-no-full-admin-policy", c))
	if got.Status != StatusUnknown {
		t.Errorf("status = %q, want unknown", got.Status)
	}
}

// 付与済みかつ顧客管理のものだけを見に行くこと。
// AWS 管理ポリシー (AdministratorAccess) まで挙げると、正当な管理者運用が
// 毎回 high で上がって一覧が実務に耐えない。
func TestPolicyScopeIsLocalAndAttached(t *testing.T) {
	var gotScope iamtypes.PolicyScopeType
	var gotAttached bool
	c := baseClients()
	c.IAM = policyScopeSpy{onList: func(in *iam.ListPoliciesInput) {
		gotScope, gotAttached = in.Scope, in.OnlyAttached
	}}

	_ = runCheck(t, "aws-iam-no-full-admin-policy", c)

	if gotScope != iamtypes.PolicyScopeTypeLocal {
		t.Errorf("Scope = %q, want Local", gotScope)
	}
	if !gotAttached {
		t.Error("OnlyAttached = false (付いていないポリシーまで挙げている)")
	}
}

type policyScopeSpy struct {
	fakeIAM
	onList func(*iam.ListPoliciesInput)
}

func (f policyScopeSpy) ListPolicies(_ context.Context, in *iam.ListPoliciesInput, _ ...func(*iam.Options)) (*iam.ListPoliciesOutput, error) {
	f.onList(in)
	return &iam.ListPoliciesOutput{}, nil
}

func (f policyScopeSpy) GetPolicyVersion(context.Context, *iam.GetPolicyVersionInput, ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error) {
	return nil, errors.New("呼ばれないはず")
}

func TestNoFullAdminPolicyIsRegistered(t *testing.T) {
	if _, ok := ChecksByID()["aws-iam-no-full-admin-policy"]; !ok {
		t.Error("aws-iam-no-full-admin-policy が Checks() に登録されていない")
	}
}
