package handlers_test

// CSPM の「未計測」が「100% 準拠」に化けていた件の再発防止。
//
// 修正前の GetPosture は cspm_findings に対して provider 列と finding 列を
// 使う SQL を発行していたが、どちらも実在しない。エラーは `_ =` と
// `if err == nil` で捨てられるため所見は 0 件になり、0 件のときは
// compliance を 100/100/100、posture_score を 100 として返していた。
// つまりクエリが壊れているという事実が、画面上は
// 「CIS 100% / SOC 2 100% / ISO 27001 100%、100 点 (A 判定)」という
// 最も安心できる表示になっていた。
//
// ここで押さえるのは 3 点:
//  1. データが無いときに 100% を返さない (data_available=false)
//  2. cspm_findings は cspm_accounts と結合してプロバイダで絞れる
//  3. 空の cspm_findings に阻まれず cloud_misconfigurations へ到達できる

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/edr-platform/server/internal/api/handlers"
)

type cloudPostureBody struct {
	Provider           string             `json:"provider"`
	PostureScore       float64            `json:"posture_score"`
	Findings           map[string]int     `json:"findings"`
	Compliance         map[string]float64 `json:"compliance"`
	Misconfigurations  []map[string]any   `json:"misconfigurations"`
	ResourcesMonitored int                `json:"resources_monitored"`
	DataAvailable      bool               `json:"data_available"`
}

func getPosture(t *testing.T, pool *pgxpool.Pool, provider string) cloudPostureBody {
	t.Helper()
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/cloud/posture?provider="+provider, nil)
	handlers.NewCloudPostureHandler(pool).GetPosture(c)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", w.Code, w.Body.String())
	}
	var body cloudPostureBody
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("レスポンスが JSON として読めない: %v (body=%s)", err, w.Body.String())
	}
	return body
}

// 所見が 1 件も無いプロバイダでは「準拠 100%」を名乗らない。
func TestCloudPosture_NoDataIsNotFullCompliance(t *testing.T) {
	pool := testPool(t)

	// 実在しないプロバイダなら、他テストが入れた行に影響されず必ず 0 件。
	got := getPosture(t, pool, "itest-empty-provider")

	if got.DataAvailable {
		t.Fatalf("データが無いのに data_available=true")
	}
	for _, framework := range []string{"cis", "soc2", "iso27001"} {
		if got.Compliance[framework] != 0 {
			t.Errorf("compliance[%s] = %v, want 0 (未計測を 100%% と偽らない)",
				framework, got.Compliance[framework])
		}
	}
	if got.PostureScore != 0 {
		t.Errorf("posture_score = %v, want 0", got.PostureScore)
	}
}

// cspm_findings は provider 列を持たないので cspm_accounts と結合する必要がある。
// 修正前はこのクエリが実行時エラーになり、所見が常に 0 件だった。
func TestCloudPosture_ReadsCspmFindingsViaAccountJoin(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	// cloud_provider は CHECK 制約で aws/azure/gcp/alibaba に限られる。
	// 他テストと衝突しにくい alibaba を使う。
	const provider = "alibaba"

	// 前回の実行が途中で落ちていた場合の残骸を先に消す。残っていると
	// 件数が水増しされて落ちる。cspm_findings は account_id に
	// ON DELETE CASCADE が張られているので親を消せば一緒に消える。
	cleanup := func() {
		if _, err := pool.Exec(ctx,
			`DELETE FROM cspm_accounts WHERE account_name='itest-cspm-account'`); err != nil {
			t.Errorf("後片付けに失敗しました (cspm_accounts): %v", err)
		}
	}
	cleanup()
	t.Cleanup(cleanup)

	var accountID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO cspm_accounts (cloud_provider, account_id, account_name)
		 VALUES ($1, '000000000000', 'itest-cspm-account')
		 RETURNING id::text`, provider).Scan(&accountID); err != nil {
		t.Fatalf("seed cspm_accounts: %v", err)
	}

	// 所見の同一性は (アカウント, チェック, 資源, リージョン) で決まる
	// (migration 381 の uq_cspm_findings_identity)。あるチェックはある資源に
	// 対して通るか落ちるかのどちらかなので、チェックと資源を別々にする。
	for _, f := range []struct{ sev, checkID, check, resource string }{
		{"critical", "CIS-2.1.5", "S3 バケットが公開されています", "arn:aws:s3:::itest"},
		{"high", "CIS-1.5", "ルートアカウントに MFA がありません", "root"},
		{"medium", "CIS-3.1", "CloudTrail が無効です", "trail-itest"},
	} {
		if _, err := pool.Exec(ctx,
			`INSERT INTO cspm_findings
			   (account_id, resource_type, resource_id, resource_name, region,
			    check_id, check_name, severity, status, remediation)
			 VALUES ($1::uuid, 's3', $2, 'itest-bucket', 'ap-northeast-1',
			         $3, $4, $5, 'open', '公開設定を解除してください')`,
			accountID, f.resource, f.checkID, f.check, f.sev); err != nil {
			t.Fatalf("seed cspm_findings (%s): %v", f.sev, err)
		}
	}

	got := getPosture(t, pool, provider)

	if !got.DataAvailable {
		t.Fatal("cspm_findings に行があるのに data_available=false (結合が効いていない)")
	}
	if got.Findings["critical"] != 1 || got.Findings["high"] != 1 || got.Findings["medium"] != 1 {
		t.Errorf("findings = %v, want critical/high/medium 各 1", got.Findings)
	}
	// 100 - (1*5 + 1*2 + 1*0.5) = 92.5
	if got.PostureScore != 92.5 {
		t.Errorf("posture_score = %v, want 92.5", got.PostureScore)
	}
	if got.Compliance["cis"] == 100 {
		t.Error("所見があるのに CIS が 100% になっている")
	}
	if len(got.Misconfigurations) != 3 {
		t.Fatalf("misconfigurations = %d 件, want 3", len(got.Misconfigurations))
	}
	// 重大度順に並び、finding は check_name (旧実装が読もうとした finding 列は無い)。
	first := got.Misconfigurations[0]
	if first["severity"] != "critical" {
		t.Errorf("先頭の severity = %v, want critical", first["severity"])
	}
	if first["finding"] != "S3 バケットが公開されています" {
		t.Errorf("finding = %v, want check_name の値", first["finding"])
	}
	if first["id"] == "" || first["id"] == nil {
		t.Error("id が空 (実 ID を返していない)")
	}
}

// スキャナが未実装なのに「スキャン完了」と報告していた件の再発防止。
//
// 修正前は無条件に 200 と status:"running" を返しており、画面はそれを受けて
// 進捗バーを 100% まで進め、緑で「スキャン完了 — 全プロバイダーのポスチャーを
// 更新しました」と表示していた。実際にはどのクラウドにも接続していない。
// 実施していない監査を実施したと報告しないことを保証する。
func TestCloudPosture_ScanDoesNotClaimSuccess(t *testing.T) {
	pool := testPool(t)
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/cloud/scan", nil)
	handlers.NewCloudPostureHandler(pool).TriggerScan(c)

	if w.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501 (body=%s)", w.Code, w.Body.String())
	}

	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("レスポンスが JSON として読めない: %v", err)
	}
	if body["code"] != "cspm_scanner_not_implemented" {
		t.Errorf("code = %v, want cspm_scanner_not_implemented", body["code"])
	}
	// apiFetch は error フィールドを例外メッセージとして画面に出す。
	if msg, _ := body["error"].(string); msg == "" {
		t.Error("error フィールドが空 (画面に理由が出ない)")
	}
	// 実行中・完了を示すフィールドを返してはいけない。
	for _, k := range []string{"status", "started_at"} {
		if _, present := body[k]; present {
			t.Errorf("%q を返している — スキャンが動いていると誤解させる", k)
		}
	}
}

// 空の cspm_findings が存在するだけで cloud_misconfigurations に到達できない、
// という取得元選択のバグの再発防止。修正前は tableExists だけで選んでいたため
// cspm_findings が常に勝ち、フォールバックが永久に死んでいた。
func TestCloudPosture_FallsBackToCloudMisconfigurations(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	const provider = "itest-fallback"
	cleanup := func() {
		if _, err := pool.Exec(ctx,
			`DELETE FROM cloud_misconfigurations WHERE provider=$1`, provider); err != nil {
			t.Errorf("後片付けに失敗しました (cloud_misconfigurations): %v", err)
		}
	}
	cleanup()
	t.Cleanup(cleanup)

	if _, err := pool.Exec(ctx,
		`INSERT INTO cloud_misconfigurations
		   (workload_id, workload_name, provider, issue_type, severity,
		    description, remediation, status, region)
		 VALUES ('wl-1', 'itest-workload', $1, 'public_bucket', 'high',
		         'バケットが公開されています', '公開設定を解除してください', 'open', 'ap-northeast-1')`,
		provider); err != nil {
		t.Fatalf("seed cloud_misconfigurations: %v", err)
	}

	got := getPosture(t, pool, provider)

	if !got.DataAvailable {
		t.Fatal("cloud_misconfigurations に行があるのに data_available=false (フォールバック不到達)")
	}
	if got.Findings["high"] != 1 {
		t.Errorf("findings = %v, want high 1", got.Findings)
	}
	if len(got.Misconfigurations) != 1 {
		t.Fatalf("misconfigurations = %d 件, want 1", len(got.Misconfigurations))
	}
	m := got.Misconfigurations[0]
	if m["resource_id"] != "itest-workload" {
		t.Errorf("resource_id = %v, want workload_name の値", m["resource_id"])
	}
	if m["finding"] != "バケットが公開されています" {
		t.Errorf("finding = %v, want description の値", m["finding"])
	}
}
