package awsscan

// 認証情報レポートの解析と、それを使う 3 項目 (CIS 1.10 / 1.12 / 1.14)。
//
// 実アカウント検証で「テストは存在したが入力の型が足りていなかった」欠陥を
// 3 件出しているので (docs/results/live-20260813-cspm-aws-first-scan.md)、
// ここでは値の「形」を意識的に散らしてある。特に AWS が「値が無い」を
// 3 通り (not_supported / N/A / no_information) で表すところは、
// 全部のケースを作る。

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

const credReportHeader = "user,arn,user_creation_time,password_enabled,password_last_used," +
	"password_last_changed,password_next_rotation,mfa_active," +
	"access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date," +
	"access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date\n"

func TestParseCredentialReportHandlesMissingValueForms(t *testing.T) {
	csv := credReportHeader +
		// ルート: パスワード欄が not_supported。
		"<root_account>,arn:aws:iam::123456789012:root,2020-01-01T00:00:00+00:00," +
		"not_supported,2026-08-01T00:00:00+00:00,not_supported,not_supported,true," +
		"false,N/A,N/A,false,N/A,N/A\n" +
		// 一度もログインしていないユーザー: no_information。
		"never-logged-in,arn:aws:iam::123456789012:user/never-logged-in,2026-01-01T00:00:00+00:00," +
		"true,no_information,2026-01-01T00:00:00+00:00,N/A,false," +
		"false,N/A,N/A,false,N/A,N/A\n" +
		// キーを 2 本持つユーザー。
		"two-keys,arn:aws:iam::123456789012:user/two-keys,2025-01-01T00:00:00+00:00," +
		"false,N/A,N/A,N/A,false," +
		"true,2025-02-01T00:00:00+00:00,2026-08-10T00:00:00+00:00," +
		"true,2026-07-01T00:00:00+00:00,no_information\n"

	rows, err := parseCredentialReport([]byte(csv))
	if err != nil {
		t.Fatalf("parseCredentialReport: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("行数 = %d, want 3", len(rows))
	}

	root := rows[0]
	if !root.IsRoot() {
		t.Error("ルート行が IsRoot で判定できない")
	}
	// not_supported を true と読むと、ルートに「パスワードあり MFA 無し」の
	// 所見が立ちかねない。
	if root.PasswordEnabled {
		t.Error("not_supported を有効と読んでいる")
	}
	if !root.MFAActive {
		t.Error("ルートの mfa_active=true が読めていない")
	}

	never := rows[1]
	if !never.PasswordEnabled {
		t.Error("password_enabled=true が読めていない")
	}
	// ここが要。no_information をゼロ値の時刻にすると 1970 年扱いになり、
	// 作りたてのユーザーが「長期未使用」に化ける。
	if never.PasswordLastUsed != nil {
		t.Errorf("no_information が時刻として読まれている: %v", never.PasswordLastUsed)
	}
	if never.CreatedAt == nil || never.CreatedAt.Year() != 2026 {
		t.Errorf("user_creation_time が読めていない: %v", never.CreatedAt)
	}

	two := rows[2]
	if !two.Keys[0].Active || !two.Keys[1].Active {
		t.Error("2 本のキーが両方 active として読めていない")
	}
	if two.Keys[0].LastUsed == nil {
		t.Error("キー 1 の最終使用日が読めていない")
	}
	if two.Keys[1].LastUsed != nil {
		t.Error("キー 2 の no_information が時刻として読まれている")
	}
	if two.Keys[1].LastRotated == nil {
		t.Error("キー 2 の最終更新日が読めていない")
	}
}

// 列が増減しても、既知の列は名前で正しく引けること。
// 位置で引く実装だと AWS が列を足した瞬間に全部ずれる。
func TestParseCredentialReportUsesColumnNames(t *testing.T) {
	csv := "arn,user,mfa_active,password_enabled,future_new_column,user_creation_time\n" +
		"arn:aws:iam::123456789012:user/alice,alice,true,true,something,2025-01-01T00:00:00+00:00\n"
	rows, err := parseCredentialReport([]byte(csv))
	if err != nil {
		t.Fatalf("parseCredentialReport: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("行数 = %d, want 1", len(rows))
	}
	if rows[0].User != "alice" || !rows[0].MFAActive || !rows[0].PasswordEnabled {
		t.Errorf("列を名前で引けていない: %+v", rows[0])
	}
}

func TestCredentialReportGeneratesWhenMissing(t *testing.T) {
	calls := 0
	c := baseClients()
	c.IAM = fakeIAM{
		generateCalls: &calls,
		readyReport: credReportHeader +
			"alice,arn:aws:iam::123456789012:user/alice,2025-01-01T00:00:00+00:00," +
			"true,2026-08-13T00:00:00+00:00,2025-01-01T00:00:00+00:00,N/A,false," +
			"false,N/A,N/A,false,N/A,N/A\n",
	}

	got := runCheck(t, "aws-iam-user-mfa", c)
	if len(got) != 1 {
		t.Fatalf("結果が %d 件, want 1: %+v", len(got), got)
	}
	if got[0].Status != StatusFail {
		t.Errorf("MFA 無しユーザーの status = %q, want fail", got[0].Status)
	}
	if calls != 1 {
		t.Errorf("GenerateCredentialReport の呼び出しが %d 回, want 1", calls)
	}
}

// レポートが読めなければ unknown。pass に倒すと「IAM ユーザーに問題なし」
// という最も安心できる表示になる。
func TestCredentialReportFailureIsUnknown(t *testing.T) {
	c := baseClients()
	c.IAM = fakeIAM{reportErr: errAccessDenied{}}
	for _, id := range []string{"aws-iam-user-mfa", "aws-iam-unused-credentials", "aws-iam-access-key-rotation"} {
		got := onlyResult(t, runCheck(t, id, c))
		if got.Status != StatusUnknown {
			t.Errorf("%s: status = %q, want unknown", id, got.Status)
		}
	}
}

type errAccessDenied struct{}

func (errAccessDenied) Error() string { return "AccessDenied" }

func TestUserMFASkipsRootAndPasswordlessUsers(t *testing.T) {
	c := baseClients()
	c.IAM = fakeIAM{report: credReportHeader +
		// ルート: MFA 無しでも aws-iam-root-mfa が見るのでここでは出さない。
		"<root_account>,arn:aws:iam::123456789012:root,2020-01-01T00:00:00+00:00," +
		"not_supported,2026-08-01T00:00:00+00:00,not_supported,not_supported,false," +
		"false,N/A,N/A,false,N/A,N/A\n" +
		// パスワードを持たない (プログラム用) ユーザー: コンソールに入れないので対象外。
		"svc-account,arn:aws:iam::123456789012:user/svc-account,2025-01-01T00:00:00+00:00," +
		"false,N/A,N/A,N/A,false," +
		"true,2026-08-01T00:00:00+00:00,2026-08-10T00:00:00+00:00,false,N/A,N/A\n" +
		// 対象。
		"bob,arn:aws:iam::123456789012:user/bob,2025-01-01T00:00:00+00:00," +
		"true,2026-08-10T00:00:00+00:00,2025-01-01T00:00:00+00:00,N/A,true," +
		"false,N/A,N/A,false,N/A,N/A\n",
	}

	got := runCheck(t, "aws-iam-user-mfa", c)
	if len(got) != 1 {
		t.Fatalf("結果が %d 件, want 1 (ルートかパスワード無しを拾っている): %+v", len(got), got)
	}
	if got[0].ResourceID != "bob" || got[0].Status != StatusPass {
		t.Errorf("想定外の結果: %+v", got[0])
	}
}

func TestUnusedCredentials(t *testing.T) {
	now := time.Date(2026, 8, 14, 0, 0, 0, 0, time.UTC)
	c := baseClients()

	mk := func(line string) []credentialRow {
		t.Helper()
		rows, err := parseCredentialReport([]byte(credReportHeader + line))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		return rows
	}

	for _, tc := range []struct {
		name string
		line string
		want Status
		// evidence に含まれてほしい語。所見だけで何を止めるべきか分かること。
		contains string
	}{
		{
			"最近使ったパスワードは合格",
			"alice,arn,2025-01-01T00:00:00+00:00,true,2026-08-10T00:00:00+00:00,2025-01-01T00:00:00+00:00,N/A,true,false,N/A,N/A,false,N/A,N/A\n",
			StatusPass, "",
		},
		{
			"45 日以上前のパスワードは不合格",
			"stale,arn,2025-01-01T00:00:00+00:00,true,2026-05-01T00:00:00+00:00,2025-01-01T00:00:00+00:00,N/A,true,false,N/A,N/A,false,N/A,N/A\n",
			StatusFail, "パスワードの最終使用",
		},
		{
			// 一度も使われていない かつ 作成が古い → 未使用。
			"未使用で作成が古いパスワードは不合格",
			"ghost,arn,2025-01-01T00:00:00+00:00,true,no_information,2025-01-01T00:00:00+00:00,N/A,true,false,N/A,N/A,false,N/A,N/A\n",
			StatusFail, "一度も使われていません",
		},
		{
			// 作りたてで未使用なだけのユーザーを叩かない。
			"作成直後で未使用なら合格",
			"fresh,arn,2026-08-13T00:00:00+00:00,true,no_information,2026-08-13T00:00:00+00:00,N/A,true,false,N/A,N/A,false,N/A,N/A\n",
			StatusPass, "",
		},
		{
			// contains は語の区切りまで含める。実アカウント検証で
			// 「アクセスキー 1の最終使用が」と助詞が詰まって出たため
			// (項目によって表記が揺れていた)。所見は作業指示なので揃える。
			"長期未使用のアクセスキーは不合格",
			"keyuser,arn,2025-01-01T00:00:00+00:00,false,N/A,N/A,N/A,false,true,2025-01-01T00:00:00+00:00,2026-01-01T00:00:00+00:00,false,N/A,N/A\n",
			StatusFail, "アクセスキー 1 の最終使用が",
		},
		{
			"一度も使われていないキーの表記も揃っていること",
			"unusedkey,arn,2025-01-01T00:00:00+00:00,false,N/A,N/A,N/A,false,true,2025-01-01T00:00:00+00:00,N/A,false,N/A,N/A\n",
			StatusFail, "アクセスキー 1 が一度も使われていません",
		},
		{
			// 無効なキーは対象外。無効化済みのものを挙げても打ち手が無い。
			"無効なキーは対象外",
			"disabled,arn,2025-01-01T00:00:00+00:00,false,N/A,N/A,N/A,false,false,2020-01-01T00:00:00+00:00,2020-01-01T00:00:00+00:00,false,N/A,N/A\n",
			"", "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := evalUnusedCredentials(mk(tc.line), now, c, "aws-iam-unused-credentials")
			if tc.want == "" {
				if len(got) != 0 {
					t.Fatalf("対象外のはずが %d 件出た: %+v", len(got), got)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("結果が %d 件, want 1: %+v", len(got), got)
			}
			if got[0].Status != tc.want {
				t.Errorf("status = %q, want %q (evidence: %s)", got[0].Status, tc.want, got[0].Evidence)
			}
			if tc.contains != "" && !strings.Contains(got[0].Evidence, tc.contains) {
				t.Errorf("evidence = %q, %q を含んでいない", got[0].Evidence, tc.contains)
			}
		})
	}
}

func TestAccessKeyRotation(t *testing.T) {
	now := time.Date(2026, 8, 14, 0, 0, 0, 0, time.UTC)
	c := baseClients()

	mk := func(line string) []credentialRow {
		t.Helper()
		rows, err := parseCredentialReport([]byte(credReportHeader + line))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		return rows
	}

	for _, tc := range []struct {
		name string
		line string
		want Status
	}{
		{
			"90 日以内なら合格",
			"fresh,arn,2025-01-01T00:00:00+00:00,false,N/A,N/A,N/A,false,true,2026-07-01T00:00:00+00:00,2026-08-10T00:00:00+00:00,false,N/A,N/A\n",
			StatusPass,
		},
		{
			"90 日超は不合格",
			"old,arn,2025-01-01T00:00:00+00:00,false,N/A,N/A,N/A,false,true,2026-01-01T00:00:00+00:00,2026-08-10T00:00:00+00:00,false,N/A,N/A\n",
			StatusFail,
		},
		{
			// 世代が読めないキーを pass に倒すと、実際には古いキーが
			// 「問題なし」として通る。
			"最終更新日が読めなければ unknown",
			"unreadable,arn,2025-01-01T00:00:00+00:00,false,N/A,N/A,N/A,false,true,N/A,2026-08-10T00:00:00+00:00,false,N/A,N/A\n",
			StatusUnknown,
		},
		{
			"2 本のうち片方が古ければ不合格",
			"mixed,arn,2025-01-01T00:00:00+00:00,false,N/A,N/A,N/A,false,true,2026-08-01T00:00:00+00:00,2026-08-10T00:00:00+00:00,true,2026-01-01T00:00:00+00:00,2026-08-10T00:00:00+00:00\n",
			StatusFail,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := evalAccessKeyRotation(mk(tc.line), now, c, "aws-iam-access-key-rotation")
			if len(got) != 1 {
				t.Fatalf("結果が %d 件, want 1: %+v", len(got), got)
			}
			if got[0].Status != tc.want {
				t.Errorf("status = %q, want %q (evidence: %s)", got[0].Status, tc.want, got[0].Evidence)
			}
		})
	}
}

// 追加した 3 項目が Checks() に載っていること。
// 定義しただけで登録し忘れると、テストは緑のまま実運用で 1 度も走らない。
func TestWave2ChecksAreRegistered(t *testing.T) {
	byID := ChecksByID()
	for _, id := range []string{
		"aws-iam-user-mfa",
		"aws-iam-unused-credentials",
		"aws-iam-access-key-rotation",
	} {
		if _, ok := byID[id]; !ok {
			t.Errorf("%s が Checks() に登録されていない", id)
		}
	}
}

// unknown が Results ではなく Errors に行くこと。
// レポートが読めないときに所見 0 件で completed になると、
// 「IAM に問題なし」という表示になる。
func TestCredentialChecksUnknownDoesNotBecomeFinding(t *testing.T) {
	s := NewScanner()
	res := &ScanResult{}
	c := baseClients()
	c.IAM = fakeIAM{reportErr: errAccessDenied{}}

	s.runOne(context.Background(), ChecksByID()["aws-iam-user-mfa"], c, res, &sync.Mutex{})

	if len(res.Results) != 0 {
		t.Errorf("unknown が所見になっている: %+v", res.Results)
	}
	if len(res.Errors) != 1 {
		t.Fatalf("Errors = %d 件, want 1", len(res.Errors))
	}
	if len(res.Completed) != 0 {
		t.Error("読めなかった組が完走扱いになっている")
	}
}
