package awsscan

// CIS 1.16 — 管理者権限 (*:*) を与えるポリシーが誰かに付いていないか。
//
// 対象は「顧客が作って、実際に誰かに付いている」ポリシーだけ。
//
//   - Scope=Local: AWS 管理ポリシーを除く。CIS の監査手順もこの範囲を見る。
//     AdministratorAccess を持つ管理者は多くの組織で正当なので、これを
//     毎回 critical で挙げると一覧が実務に耐えない。自作の広すぎる
//     ポリシーのほうが「気づかず作ってしまった」可能性が高い。
//   - OnlyAttached=true: どこにも付いていないポリシーは、その時点では
//     誰の権限にもなっていない。付いていないものを挙げると、打ち手が
//     「消す」しか無い所見で一覧が埋まる。
//
// ポリシー文書は URL エンコードされた JSON で返る。Action と Resource は
// 文字列にも配列にもなる ---この揺れを片方しか扱わないと、もう片方の形の
// ポリシーが黙って検査対象から外れる。

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// policyDocument は IAM ポリシー文書。
type policyDocument struct {
	Statement []policyStatement `json:"Statement"`
}

// policyStatement の Action / Resource は文字列と配列のどちらでも来る。
// stringOrSlice でその両方を受ける。
type policyStatement struct {
	Effect   string        `json:"Effect"`
	Action   stringOrSlice `json:"Action"`
	Resource stringOrSlice `json:"Resource"`
	// NotAction がある文はここでは判定しない (下の grantsFullAdmin を参照)。
	NotAction stringOrSlice `json:"NotAction"`
	// Condition が付いていれば無条件の許可ではない。
	Condition json.RawMessage `json:"Condition"`
}

// stringOrSlice は JSON の "a" と ["a","b"] を同じに扱う。
type stringOrSlice []string

func (s *stringOrSlice) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*s = []string{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*s = many
	return nil
}

func (s stringOrSlice) has(v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// parsePolicyDocument は URL エンコードされた JSON を読む。
func parsePolicyDocument(encoded string) (*policyDocument, error) {
	decoded, err := url.QueryUnescape(encoded)
	if err != nil {
		// エンコードされていない文書が返ることもある。素の JSON として試す。
		decoded = encoded
	}
	var doc policyDocument
	if err := json.Unmarshal([]byte(decoded), &doc); err != nil {
		return nil, fmt.Errorf("ポリシー文書の解析に失敗: %w", err)
	}
	return &doc, nil
}

// grantsFullAdmin は「無条件で全 action × 全 resource を許す」文があるか。
//
// 条件を厳密に取る:
//
//   - Effect が Allow
//   - Action に "*" が含まれる (「s3:*」のようなサービス全権は対象外。
//     広いには違いないが CIS 1.16 が問うのは *:* なので、ここを緩めると
//     正当な運用ポリシーまで critical で挙がる)
//   - Resource に "*" が含まれる
//   - Condition が付いていない (MFA 必須などが付いていれば無条件ではない)
//   - NotAction が無い (NotAction 付きは意味が反転するので、ここでは
//     判定しない ---誤判定するくらいなら対象外にする)
func (d *policyDocument) grantsFullAdmin() bool {
	for _, st := range d.Statement {
		if !strings.EqualFold(st.Effect, "Allow") {
			continue
		}
		if len(st.NotAction) > 0 {
			continue
		}
		if len(st.Condition) > 0 && string(st.Condition) != "null" && string(st.Condition) != "{}" {
			continue
		}
		if st.Action.has("*") && st.Resource.has("*") {
			return true
		}
	}
	return false
}

// attachedLocalPolicies は顧客管理かつ付与済みのポリシーを全ページ取る。
func attachedLocalPolicies(ctx context.Context, c *Clients) ([]iamtypes.Policy, error) {
	var out []iamtypes.Policy
	var marker *string
	for {
		page, err := c.IAM.ListPolicies(ctx, &iam.ListPoliciesInput{
			Scope:        iamtypes.PolicyScopeTypeLocal,
			OnlyAttached: true,
			Marker:       marker,
		})
		if err != nil {
			return nil, err
		}
		out = append(out, page.Policies...)
		if !page.IsTruncated || page.Marker == nil {
			return out, nil
		}
		marker = page.Marker
	}
}

func checkNoFullAdminPolicy() Check {
	const id = "aws-iam-no-full-admin-policy"
	return Check{
		ID:          id,
		Title:       "管理者権限 (*:*) を与える自作ポリシーが付与されていない",
		Description: "全 action × 全 resource を許すポリシーは、1 つ漏れただけでアカウント全体の掌握につながる。",
		Severity:    SeverityHigh,
		Scope:       ScopeAccount,
		Service:     "IAM",
		Frameworks:  []string{"CIS-AWS-1.16"},
		Remediation: "そのポリシーを外し、実際に必要な action と resource だけを列挙したポリシーに置き換えてください。管理作業には AWS 管理ポリシーか、条件付き (MFA 必須など) のロールを使ってください。",
		Run: func(ctx context.Context, c *Clients) []Result {
			policies, err := attachedLocalPolicies(ctx, c)
			if err != nil {
				return unknownOne(id, c, "ポリシー一覧の取得に失敗: "+err.Error())
			}

			var out []Result
			for _, p := range policies {
				name := aws.ToString(p.PolicyName)
				arn := aws.ToString(p.Arn)
				res := Result{
					CheckID: id, ResourceID: arn, ResourceName: name,
					ResourceType: "AwsIamPolicy", Region: c.Region,
				}

				ver, err := c.IAM.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
					PolicyArn: p.Arn,
					VersionId: p.DefaultVersionId,
				})
				if err != nil {
					// 1 本読めなかっただけで全体を落とさない。読めなかった
					// ものは unknown にして、残りの判定は続ける。
					res.Status = StatusUnknown
					res.Evidence = "ポリシー文書の取得に失敗: " + err.Error()
					out = append(out, res)
					continue
				}
				doc, err := parsePolicyDocument(aws.ToString(ver.PolicyVersion.Document))
				if err != nil {
					res.Status = StatusUnknown
					res.Evidence = err.Error()
					out = append(out, res)
					continue
				}

				if doc.grantsFullAdmin() {
					res.Status = StatusFail
					res.Evidence = fmt.Sprintf(
						"全 action × 全 resource を無条件に許可しています (付与先 %d 件)",
						aws.ToInt32(p.AttachmentCount))
				} else {
					res.Status = StatusPass
					res.Evidence = "管理者権限の無条件付与はありません"
				}
				out = append(out, res)
			}
			return out
		},
	}
}
