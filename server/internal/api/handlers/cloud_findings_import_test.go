package handlers_test

// CSPM 所見の取り込み口。
//
// 押さえるのは「再取り込みで壊れないこと」と「運用判断を上書きしないこと」。
// 取り込みは CI や cron から繰り返し叩かれる前提なので、2 回目以降で行が
// 増えたり、担当者が抑止した所見が勝手に open に戻ったりすると使えない。

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/edr-platform/server/internal/api/handlers"
)

const importTestAccountID = "999900001111"

type importResponse struct {
	AccountID string   `json:"account_id"`
	Imported  int      `json:"imported"`
	Resolved  int      `json:"resolved"`
	Rejected  int      `json:"rejected"`
	Errors    []string `json:"errors"`
}

// postImport は取り込み口を 1 回叩く。role は JWT ミドルウェアが入れる値。
func postImport(t *testing.T, pool *pgxpool.Pool, role, body string) (int, importResponse) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/cloud/findings/import",
		strings.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")
	if role != "" {
		c.Set("role", role)
	}
	handlers.NewCloudPostureHandler(pool).ImportFindings(c)

	var out importResponse
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// cleanImportAccount は取り込み先アカウントと、そこに紐づく所見を消す
// (cspm_findings は account_id に ON DELETE CASCADE)。
func cleanImportAccount(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	del := func() {
		if _, err := pool.Exec(ctx,
			`DELETE FROM cspm_accounts WHERE account_id = $1`, importTestAccountID); err != nil {
			t.Errorf("後片付けに失敗しました (cspm_accounts): %v", err)
		}
	}
	del()
	t.Cleanup(del)
}

func importBody(findings string) string {
	return fmt.Sprintf(`{"provider":"aws","account_id":%q,"account_name":"itest-import","findings":[%s]}`,
		importTestAccountID, findings)
}

// 同じ内容を 2 回取り込んでも行は増えず、last_seen_at だけが進む。
func TestCSPMImport_IsIdempotent(t *testing.T) {
	pool := testPool(t)
	cleanImportAccount(t, pool)
	ctx := context.Background()

	body := importBody(`
		{"check_id":"s3_public","check_name":"S3 が公開されています","severity":"critical",
		 "status":"FAIL","resource_type":"AwsS3Bucket","resource_id":"arn:aws:s3:::itest",
		 "resource_name":"itest","region":"ap-northeast-1",
		 "remediation":"公開設定を解除してください","compliance_frameworks":["CIS","SOC2"]},
		{"check_id":"root_mfa","check_name":"root に MFA がありません","severity":"high",
		 "status":"FAIL","resource_type":"AwsAccount","resource_id":"root","region":""}`)

	code, first := postImport(t, pool, "admin", body)
	if code != http.StatusOK {
		t.Fatalf("1 回目 status = %d, want 200 (errors=%v)", code, first.Errors)
	}
	if first.Imported != 2 || first.Rejected != 0 {
		t.Fatalf("1 回目 = %+v, want imported 2 / rejected 0", first)
	}

	var firstSeen, lastSeen string
	if err := pool.QueryRow(ctx, `
		SELECT MIN(first_seen_at)::text, MAX(last_seen_at)::text
		FROM cspm_findings WHERE account_id = $1::uuid`, first.AccountID).
		Scan(&firstSeen, &lastSeen); err != nil {
		t.Fatalf("1 回目の時刻取得: %v", err)
	}

	code, second := postImport(t, pool, "admin", body)
	if code != http.StatusOK {
		t.Fatalf("2 回目 status = %d, want 200", code)
	}

	var count int
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM cspm_findings WHERE account_id = $1::uuid`,
		second.AccountID).Scan(&count); err != nil {
		t.Fatalf("件数取得: %v", err)
	}
	if count != 2 {
		t.Errorf("2 回取り込んだ後の件数 = %d, want 2 (重複している)", count)
	}

	var firstSeen2, lastSeen2 string
	if err := pool.QueryRow(ctx, `
		SELECT MIN(first_seen_at)::text, MAX(last_seen_at)::text
		FROM cspm_findings WHERE account_id = $1::uuid`, second.AccountID).
		Scan(&firstSeen2, &lastSeen2); err != nil {
		t.Fatalf("2 回目の時刻取得: %v", err)
	}
	if firstSeen2 != firstSeen {
		t.Errorf("first_seen_at が動いている: %s → %s (初回検知時刻が失われる)", firstSeen, firstSeen2)
	}
	if lastSeen2 == lastSeen {
		t.Errorf("last_seen_at が更新されていない (%s のまま)", lastSeen)
	}
}

// 取り込んだ所見が /cloud/posture に出る = data_available が true になる。
// ここが繋がっていないと、取り込んでも画面は「未計測」のままになる。
func TestCSPMImport_ShowsUpInPosture(t *testing.T) {
	pool := testPool(t)
	cleanImportAccount(t, pool)

	code, res := postImport(t, pool, "admin", importBody(`
		{"check_id":"sg_open_ssh","check_name":"SSH が全世界に開放されています","severity":"critical",
		 "status":"FAIL","resource_type":"AwsSecurityGroup","resource_id":"sg-itest","region":"us-east-1"}`))
	if code != http.StatusOK || res.Imported != 1 {
		t.Fatalf("取り込みに失敗: code=%d res=%+v", code, res)
	}

	got := getPosture(t, pool, "aws")
	if !got.DataAvailable {
		t.Fatal("取り込んだのに data_available=false (posture から見えていない)")
	}
	if got.Findings["critical"] < 1 {
		t.Errorf("critical = %d, want >= 1", got.Findings["critical"])
	}
	if got.PostureScore == 0 || got.PostureScore >= 100 {
		t.Errorf("posture_score = %v, want 0 < score < 100", got.PostureScore)
	}
}

// PASS で報告された項目は所見にせず、既に開いていれば解消として扱う。
func TestCSPMImport_PassResolvesOpenFinding(t *testing.T) {
	pool := testPool(t)
	cleanImportAccount(t, pool)
	ctx := context.Background()

	fail := `{"check_id":"ebs_unencrypted","check_name":"EBS が暗号化されていません","severity":"high",
	          "status":"FAIL","resource_type":"AwsEbsVolume","resource_id":"vol-itest","region":"us-east-1"}`
	code, res := postImport(t, pool, "admin", importBody(fail))
	if code != http.StatusOK || res.Imported != 1 {
		t.Fatalf("初回取り込みに失敗: code=%d res=%+v", code, res)
	}

	pass := strings.Replace(fail, `"status":"FAIL"`, `"status":"PASS"`, 1)
	code, res2 := postImport(t, pool, "admin", importBody(pass))
	if code != http.StatusOK {
		t.Fatalf("2 回目 status = %d", code)
	}
	if res2.Imported != 0 {
		t.Errorf("imported = %d, want 0 (PASS は所見にしない)", res2.Imported)
	}
	if res2.Resolved != 1 {
		t.Errorf("resolved = %d, want 1", res2.Resolved)
	}

	var status string
	if err := pool.QueryRow(ctx,
		`SELECT status FROM cspm_findings WHERE account_id = $1::uuid AND check_id = 'ebs_unencrypted'`,
		res.AccountID).Scan(&status); err != nil {
		t.Fatalf("status 取得: %v", err)
	}
	if status != "resolved" {
		t.Errorf("status = %q, want resolved", status)
	}
}

// 担当者が抑止 (suppressed) / リスク受容した所見を、再検出で勝手に open に戻さない。
func TestCSPMImport_KeepsOperatorDecision(t *testing.T) {
	pool := testPool(t)
	cleanImportAccount(t, pool)
	ctx := context.Background()

	body := importBody(`
		{"check_id":"cloudtrail_off","check_name":"CloudTrail が無効です","severity":"high",
		 "status":"FAIL","resource_type":"AwsCloudTrail","resource_id":"trail-itest","region":"us-east-1"}`)
	code, res := postImport(t, pool, "admin", body)
	if code != http.StatusOK || res.Imported != 1 {
		t.Fatalf("初回取り込みに失敗: code=%d res=%+v", code, res)
	}

	if _, err := pool.Exec(ctx,
		`UPDATE cspm_findings SET status = 'accepted_risk' WHERE account_id = $1::uuid`,
		res.AccountID); err != nil {
		t.Fatalf("リスク受容の設定: %v", err)
	}

	if code, _ := postImport(t, pool, "admin", body); code != http.StatusOK {
		t.Fatalf("再取り込み status = %d", code)
	}

	var status string
	if err := pool.QueryRow(ctx,
		`SELECT status FROM cspm_findings WHERE account_id = $1::uuid`, res.AccountID).
		Scan(&status); err != nil {
		t.Fatalf("status 取得: %v", err)
	}
	if status != "accepted_risk" {
		t.Errorf("status = %q, want accepted_risk (運用判断が上書きされている)", status)
	}
}

// 1 件の不備で全体を落とさない。何が落ちたかは返す。
func TestCSPMImport_RejectsBadRowsWithoutFailingBatch(t *testing.T) {
	pool := testPool(t)
	cleanImportAccount(t, pool)

	code, res := postImport(t, pool, "admin", importBody(`
		{"check_id":"ok_check","check_name":"通る所見","severity":"low",
		 "status":"FAIL","resource_id":"res-ok","region":"us-east-1"},
		{"check_name":"check_id が無い","severity":"high","status":"FAIL","resource_id":"res-x"},
		{"check_id":"no_resource","severity":"high","status":"FAIL"}`))

	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (不備 1 件で全体を落とさない)", code)
	}
	if res.Imported != 1 {
		t.Errorf("imported = %d, want 1", res.Imported)
	}
	if res.Rejected != 2 {
		t.Errorf("rejected = %d, want 2", res.Rejected)
	}
	if len(res.Errors) != 2 {
		t.Errorf("errors = %v, want 2 件", res.Errors)
	}
}

// Prowler 風のキー名 (CheckID / ResourceArn / Remediation.Recommendation.Text /
// Compliance オブジェクト) も読める。
func TestCSPMImport_AcceptsProwlerStyleKeys(t *testing.T) {
	pool := testPool(t)
	cleanImportAccount(t, pool)
	ctx := context.Background()

	code, res := postImport(t, pool, "admin", importBody(`
		{"CheckID":"s3_bucket_public_access","CheckTitle":"Ensure no public S3 buckets",
		 "Severity":"critical","Status":"FAIL","ResourceType":"AwsS3Bucket",
		 "ResourceArn":"arn:aws:s3:::prowler-itest","Region":"us-east-1",
		 "StatusExtended":"Bucket is public",
		 "Remediation":{"Recommendation":{"Text":"Block public access","Url":"https://example.test"}},
		 "Compliance":{"CIS-1.5":["2.1.5"],"SOC2":["CC6.1"]}}`))
	if code != http.StatusOK || res.Imported != 1 {
		t.Fatalf("取り込みに失敗: code=%d res=%+v", code, res)
	}

	var checkName, resourceID, remediation, description string
	var frameworks []string
	if err := pool.QueryRow(ctx, `
		SELECT check_name, resource_id, COALESCE(remediation,''), COALESCE(description,''),
		       COALESCE(compliance_frameworks, '{}')
		FROM cspm_findings WHERE account_id = $1::uuid`, res.AccountID).
		Scan(&checkName, &resourceID, &remediation, &description, &frameworks); err != nil {
		t.Fatalf("行の取得: %v", err)
	}

	if checkName != "Ensure no public S3 buckets" {
		t.Errorf("check_name = %q (CheckTitle を拾えていない)", checkName)
	}
	if resourceID != "arn:aws:s3:::prowler-itest" {
		t.Errorf("resource_id = %q (ResourceArn を拾えていない)", resourceID)
	}
	if remediation != "Block public access" {
		t.Errorf("remediation = %q (Recommendation.Text を拾えていない)", remediation)
	}
	if description != "Bucket is public" {
		t.Errorf("description = %q (StatusExtended を拾えていない)", description)
	}
	if len(frameworks) != 2 {
		t.Errorf("compliance_frameworks = %v, want CIS-1.5 と SOC2 の 2 件", frameworks)
	}
}

// 閲覧専用ロールは書き込めない。
func TestCSPMImport_ViewerForbidden(t *testing.T) {
	pool := testPool(t)

	code, _ := postImport(t, pool, "viewer", importBody(`
		{"check_id":"x","severity":"low","status":"FAIL","resource_id":"r"}`))
	if code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", code)
	}
}

// provider は決められた値だけを受ける。
func TestCSPMImport_RejectsUnknownProvider(t *testing.T) {
	pool := testPool(t)

	body := `{"provider":"oracle","account_id":"1","findings":[]}`
	code, _ := postImport(t, pool, "admin", body)
	if code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", code)
	}
}

// 所見が 1 件も無い (全て PASS) アカウントは満点 100 になる。
// cspm_accounts.posture_score は NUMERIC(4,2) で最大 99.99 までしか持てず、
// 100 を書こうとすると numeric field overflow で落ちていた
// (migration 381 で 5,2 に拡張)。書き込む経路が無かったため表面化していなかった。
func TestCSPMImport_PerfectScoreFitsInColumn(t *testing.T) {
	pool := testPool(t)
	cleanImportAccount(t, pool)
	ctx := context.Background()

	code, res := postImport(t, pool, "admin", importBody(`
		{"check_id":"all_good","check_name":"問題なし","severity":"low",
		 "status":"PASS","resource_id":"res-clean","region":"us-east-1"}`))
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (errors=%v)", code, res.Errors)
	}

	var score float64
	if err := pool.QueryRow(ctx,
		`SELECT posture_score FROM cspm_accounts WHERE id = $1::uuid`, res.AccountID).
		Scan(&score); err != nil {
		t.Fatalf("posture_score 取得: %v", err)
	}
	if score != 100 {
		t.Errorf("posture_score = %v, want 100 (所見 0 件は満点)", score)
	}
}
