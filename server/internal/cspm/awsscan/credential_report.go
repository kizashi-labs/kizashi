package awsscan

// IAM 認証情報レポートを使う検査。
//
// レポートは全 IAM ユーザーの 1 行 CSV で、パスワードの有無・MFA・
// アクセスキーの世代と最終使用日が 1 回の API 呼び出しで揃う。ユーザーを
// 1 人ずつ舐めると人数分の呼び出しになるので、CIS 1.10 / 1.12 / 1.14 は
// これを起点にするのが定石。
//
// 解析で最も気をつけるのは「値が無い」の表現が 3 種類あること。
//
//	not_supported   その項目自体が存在しない (ルートのパスワード欄など)
//	N/A             設定されていない
//	no_information  設定はあるが使用記録が無い
//
// これらを 0 値や「古い日付」に丸めると判定が反転する。例えば
// password_last_used が no_information のユーザーを「最終使用が 1970 年」と
// 読むと、実際には作りたてのユーザーが「長期未使用」として上がる。逆に
// 「未使用ではない」と読むと、一度も使われていない放置アカウントを
// 見逃す。どちらも起きないよう、値が無いことを nil で持ち回る。

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

const (
	// credReportMaxWait はレポート生成を待つ上限。生成は通常数秒で終わる。
	// 待ち切れなければ unknown にする ---「待てなかった」を「問題なし」に
	// してはいけない。
	credReportMaxWait = 30 * time.Second
	// credReportPollInterval は生成完了の確認間隔。
	credReportPollInterval = 2 * time.Second

	// unusedCredentialDays は「未使用」とみなす日数 (CIS 1.12)。
	unusedCredentialDays = 45
	// keyRotationDays はアクセスキーの最大許容世代 (CIS 1.14)。
	keyRotationDays = 90

	// rootUser はレポート内でルートアカウントを表す user 列の値。
	rootUser = "<root_account>"
)

// credentialKey はアクセスキー 1 本分。
type credentialKey struct {
	Active bool
	// LastRotated は作成または最終ローテーション日。nil はキーが無い。
	LastRotated *time.Time
	// LastUsed は最終使用日。nil は「使用記録が無い」。
	LastUsed *time.Time
}

// credentialRow はレポートの 1 行 = IAM ユーザー 1 人。
type credentialRow struct {
	User string
	ARN  string
	// CreatedAt はユーザー作成日。未使用判定の基準に使う
	// (一度も使われていないユーザーは「最終使用日」が無いため)。
	CreatedAt *time.Time
	// PasswordEnabled はコンソールパスワードの有無。
	// ルートは not_supported なので false になる。
	PasswordEnabled  bool
	PasswordLastUsed *time.Time
	MFAActive        bool
	Keys             [2]credentialKey
}

// IsRoot はルートアカウントの行か。
// ルートの MFA は aws-iam-root-mfa が別に見ているので、ユーザー単位の
// 検査では除外する。同じ問題で所見が 2 件出ると、担当者は 2 回対応を
// 検討することになる。
func (r credentialRow) IsRoot() bool { return r.User == rootUser }

// credentialReport はレポートを取得して解析する。
//
// 未生成・失効なら生成を促してから読み直す。生成は数秒かかるので
// ポーリングする。
func credentialReport(ctx context.Context, c *Clients) ([]credentialRow, error) {
	out, err := c.IAM.GetCredentialReport(ctx, &iam.GetCredentialReportInput{})
	if err == nil {
		return parseCredentialReport(out.Content)
	}
	if !needsGeneration(err) {
		return nil, err
	}

	if _, gerr := c.IAM.GenerateCredentialReport(ctx, &iam.GenerateCredentialReportInput{}); gerr != nil {
		return nil, fmt.Errorf("認証情報レポートの生成に失敗: %w", gerr)
	}

	deadline := time.Now().Add(credReportMaxWait)
	for {
		out, err = c.IAM.GetCredentialReport(ctx, &iam.GetCredentialReportInput{})
		if err == nil {
			return parseCredentialReport(out.Content)
		}
		var notReady *iamtypes.CredentialReportNotReadyException
		var notPresent *iamtypes.CredentialReportNotPresentException
		if !errors.As(err, &notReady) && !errors.As(err, &notPresent) {
			return nil, err
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("認証情報レポートの生成が %s 以内に完了しませんでした", credReportMaxWait)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(credReportPollInterval):
		}
	}
}

// needsGeneration は「まだ生成されていない / 失効した」エラーか。
func needsGeneration(err error) bool {
	var notPresent *iamtypes.CredentialReportNotPresentException
	var expired *iamtypes.CredentialReportExpiredException
	var notReady *iamtypes.CredentialReportNotReadyException
	return errors.As(err, &notPresent) || errors.As(err, &expired) || errors.As(err, &notReady)
}

// parseCredentialReport は CSV を行に変換する。
//
// 列は名前で引く。位置で引くと AWS が列を足したときに全部ずれるが、
// 名前ならその列だけが欠けた扱いになる。
func parseCredentialReport(content []byte) ([]credentialRow, error) {
	if len(content) == 0 {
		return nil, errors.New("認証情報レポートが空です")
	}
	r := csv.NewReader(strings.NewReader(string(content)))
	records, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("認証情報レポートの解析に失敗: %w", err)
	}
	if len(records) < 1 {
		return nil, errors.New("認証情報レポートに見出し行がありません")
	}

	idx := map[string]int{}
	for i, name := range records[0] {
		idx[strings.TrimSpace(name)] = i
	}
	get := func(rec []string, name string) string {
		i, ok := idx[name]
		if !ok || i >= len(rec) {
			return ""
		}
		return strings.TrimSpace(rec[i])
	}

	out := make([]credentialRow, 0, len(records)-1)
	for _, rec := range records[1:] {
		if len(rec) == 0 {
			continue
		}
		row := credentialRow{
			User:             get(rec, "user"),
			ARN:              get(rec, "arn"),
			CreatedAt:        parseReportTime(get(rec, "user_creation_time")),
			PasswordEnabled:  parseReportBool(get(rec, "password_enabled")),
			PasswordLastUsed: parseReportTime(get(rec, "password_last_used")),
			MFAActive:        parseReportBool(get(rec, "mfa_active")),
		}
		for i := range row.Keys {
			n := i + 1
			row.Keys[i] = credentialKey{
				Active:      parseReportBool(get(rec, fmt.Sprintf("access_key_%d_active", n))),
				LastRotated: parseReportTime(get(rec, fmt.Sprintf("access_key_%d_last_rotated", n))),
				LastUsed:    parseReportTime(get(rec, fmt.Sprintf("access_key_%d_last_used_date", n))),
			}
		}
		out = append(out, row)
	}
	return out, nil
}

// parseReportBool は "true"/"false" を読む。
// not_supported / N/A は false。
func parseReportBool(s string) bool { return strings.EqualFold(s, "true") }

// parseReportTime は日時列を読む。値が無い場合は nil を返す。
//
// nil と「古い日付」を混同しないこと。no_information のユーザーを
// ゼロ値の time.Time として扱うと、1970 年扱いになって全員が
// 「長期未使用」に化ける。
func parseReportTime(s string) *time.Time {
	switch strings.ToLower(s) {
	case "", "n/a", "not_supported", "no_information":
		return nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05-07:00", "2006-01-02T15:04:05Z"} {
		if t, err := time.Parse(layout, s); err == nil {
			u := t.UTC()
			return &u
		}
	}
	return nil
}

// --- 検査 (CIS 1.10 / 1.12 / 1.14) ---

func checkUserMFA() Check {
	const id = "aws-iam-user-mfa"
	return Check{
		ID:          id,
		Title:       "コンソールを使える IAM ユーザーに MFA が有効",
		Description: "パスワードだけで入れるユーザーは、パスワード漏洩がそのまま侵入になる。",
		Severity:    SeverityHigh,
		Scope:       ScopeAccount,
		Service:     "IAM",
		Frameworks:  []string{"CIS-AWS-1.10"},
		Remediation: "IAM > ユーザー > セキュリティ認証情報から MFA デバイスを割り当ててください。コンソールを使わないユーザーであればパスワードを削除してください。",
		Run: func(ctx context.Context, c *Clients) []Result {
			rows, err := credentialReport(ctx, c)
			if err != nil {
				return unknownOne(id, c, "認証情報レポートの取得に失敗: "+err.Error())
			}
			var out []Result
			for _, row := range rows {
				// ルートは aws-iam-root-mfa が見る。
				// パスワードを持たないユーザーはコンソールに入れないので対象外。
				if row.IsRoot() || !row.PasswordEnabled {
					continue
				}
				res := userResult(id, c, row)
				if row.MFAActive {
					res.Status, res.Evidence = StatusPass, "MFA が有効です"
				} else {
					res.Status = StatusFail
					res.Evidence = "コンソールパスワードを持つが MFA が無効です"
				}
				out = append(out, res)
			}
			return out
		},
	}
}

func checkUnusedCredentials() Check {
	const id = "aws-iam-unused-credentials"
	return Check{
		ID:          id,
		Title:       fmt.Sprintf("%d 日以上使われていない認証情報が無効化されている", unusedCredentialDays),
		Description: "退職者や一時作業用の認証情報が残っていると、誰も見ていない侵入経路になる。",
		Severity:    SeverityMedium,
		Scope:       ScopeAccount,
		Service:     "IAM",
		Frameworks:  []string{"CIS-AWS-1.12"},
		Remediation: fmt.Sprintf("%d 日以上使われていないパスワード・アクセスキーを無効化するか削除してください。", unusedCredentialDays),
		Run: func(ctx context.Context, c *Clients) []Result {
			rows, err := credentialReport(ctx, c)
			if err != nil {
				return unknownOne(id, c, "認証情報レポートの取得に失敗: "+err.Error())
			}
			return evalUnusedCredentials(rows, time.Now().UTC(), c, id)
		},
	}
}

// evalUnusedCredentials は判定本体。now を引数に取るのはテストのため
// (時刻に依存する判定を実時間で試すと、境界のケースが書けない)。
func evalUnusedCredentials(rows []credentialRow, now time.Time, c *Clients, id string) []Result {
	cutoff := now.AddDate(0, 0, -unusedCredentialDays)
	var out []Result
	for _, row := range rows {
		if row.IsRoot() {
			continue
		}
		// 判定に使える情報が 1 つも無いユーザーは対象にしない。
		// パスワードもキーも無いユーザー (プログラム用に作って未設定など) は
		// 「未使用の認証情報」を持っていない。
		if !row.PasswordEnabled && !row.hasActiveKey() {
			continue
		}

		stale := row.staleCredentials(cutoff)
		res := userResult(id, c, row)
		if len(stale) == 0 {
			res.Status, res.Evidence = StatusPass, "有効な認証情報はいずれも最近使われています"
		} else {
			res.Status = StatusFail
			res.Evidence = strings.Join(stale, " / ")
		}
		out = append(out, res)
	}
	return out
}

// hasActiveKey は有効なアクセスキーを持っているか。
func (r credentialRow) hasActiveKey() bool {
	for _, k := range r.Keys {
		if k.Active {
			return true
		}
	}
	return false
}

// staleCredentials は cutoff より前にしか使われていない認証情報を挙げる。
//
// 「一度も使われていない」は、ユーザー作成が cutoff より前なら未使用として
// 数える。作りたてで未使用なだけのユーザーを叩かないため、作成日が
// cutoff より後ならまだ猶予があるとみなす。作成日すら読めない場合は
// 判定材料が無いので数えない (推測で所見を作らない)。
func (r credentialRow) staleCredentials(cutoff time.Time) []string {
	var stale []string
	if r.PasswordEnabled {
		if last := r.PasswordLastUsed; last != nil {
			if last.Before(cutoff) {
				stale = append(stale, "パスワードの最終使用が "+last.Format("2006-01-02"))
			}
		} else if r.CreatedAt != nil && r.CreatedAt.Before(cutoff) {
			stale = append(stale, "パスワードが一度も使われていません (作成 "+r.CreatedAt.Format("2006-01-02")+")")
		}
	}
	for i, k := range r.Keys {
		if !k.Active {
			continue
		}
		label := fmt.Sprintf("アクセスキー %d", i+1)
		if last := k.LastUsed; last != nil {
			if last.Before(cutoff) {
				stale = append(stale, label+" の最終使用が "+last.Format("2006-01-02"))
			}
			continue
		}
		// 使用記録が無いキー。作成日で猶予を判断する。
		ref := k.LastRotated
		if ref == nil {
			ref = r.CreatedAt
		}
		if ref != nil && ref.Before(cutoff) {
			stale = append(stale, label+" が一度も使われていません (作成 "+ref.Format("2006-01-02")+")")
		}
	}
	return stale
}

func checkAccessKeyRotation() Check {
	const id = "aws-iam-access-key-rotation"
	return Check{
		ID:          id,
		Title:       fmt.Sprintf("アクセスキーが %d 日以内にローテーションされている", keyRotationDays),
		Description: "長く使われるキーほど、漏洩したときに気づかれないまま使われる期間が延びる。",
		Severity:    SeverityMedium,
		Scope:       ScopeAccount,
		Service:     "IAM",
		Frameworks:  []string{"CIS-AWS-1.14"},
		Remediation: fmt.Sprintf("%d 日を超えたアクセスキーを再作成し、古いキーを無効化してから削除してください。", keyRotationDays),
		Run: func(ctx context.Context, c *Clients) []Result {
			rows, err := credentialReport(ctx, c)
			if err != nil {
				return unknownOne(id, c, "認証情報レポートの取得に失敗: "+err.Error())
			}
			return evalAccessKeyRotation(rows, time.Now().UTC(), c, id)
		},
	}
}

func evalAccessKeyRotation(rows []credentialRow, now time.Time, c *Clients, id string) []Result {
	cutoff := now.AddDate(0, 0, -keyRotationDays)
	var out []Result
	for _, row := range rows {
		if row.IsRoot() || !row.hasActiveKey() {
			continue
		}
		var old []string
		// 世代が読めないキーがあれば、そのユーザーは判定しない。
		// 「読めなかった」を pass に倒すと、実際には古いキーが
		// 「問題なし」として通ってしまう。
		unreadable := false
		for i, k := range row.Keys {
			if !k.Active {
				continue
			}
			if k.LastRotated == nil {
				unreadable = true
				continue
			}
			if k.LastRotated.Before(cutoff) {
				days := int(now.Sub(*k.LastRotated).Hours() / 24)
				old = append(old, fmt.Sprintf("アクセスキー %d が %d 日前 (%s) から未更新",
					i+1, days, k.LastRotated.Format("2006-01-02")))
			}
		}
		res := userResult(id, c, row)
		switch {
		case len(old) > 0:
			res.Status, res.Evidence = StatusFail, strings.Join(old, " / ")
		case unreadable:
			res.Status = StatusUnknown
			res.Evidence = "アクセスキーの最終更新日がレポートに含まれていません"
		default:
			res.Status = StatusPass
			res.Evidence = fmt.Sprintf("有効なアクセスキーはいずれも %d 日以内に更新されています", keyRotationDays)
		}
		out = append(out, res)
	}
	return out
}

// userResult は IAM ユーザー 1 人ぶんの結果の器。
// resource_id はユーザー名。ARN でなくユーザー名にするのは、所見一覧で
// 誰のことか一目で分かるようにするため (ARN は先頭が全員同じで読みにくい)。
func userResult(checkID string, c *Clients, row credentialRow) Result {
	return Result{
		CheckID:      checkID,
		ResourceID:   row.User,
		ResourceName: row.User,
		ResourceType: "AwsIamUser",
		Region:       c.Region,
	}
}
